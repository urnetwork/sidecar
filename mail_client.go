//go:build !ios_extension

// §15's mail on a device (R-MAIL-1, R-MAIL-3, R-MAIL-4, R-MAIL-10, R-MAIL-13, D-MAIL-6, I-7, I-9; MAIL-M7-17):
// MailClient is the root's mail component, as EvsClient is evs's, and the sdk's SidecarMail stays its wrapper. A
// Sidecar has one (Sidecar.Mail), which the "mail" component attaches to its client generations (mail_component.go).
//
//	bind      what it works on: the network's EvsClient, the AclEngine of its verified state, the core's statement
//	          poster, the zone's row, the outward-action gate and the mail routes (MailBinding). The component fills
//	          it from the Sidecar as each piece stands, and a host such as the page Worker binds its own. Until an
//	          EvsClient and an engine with a state are there, a call answers ErrMailUnbound, never a guess
//	mailbox   the member's mailbox (§15.7): an untagged device's own member's, by MailRepos.Mailbox. A tagged device
//	          has no mailbox of its own here
//	enable    ensures mailcfg (a config writer creates it, §8.8), the member's mailbox and this device's RepoAdmin of
//	          it, then POST /mail/enable, which turns on §12's mail records. Mail is on from there, or once GET
//	          /mail/status says so: it keeps a daemon from idling out (§5.8) and starts the receiver where policy
//	          grants this device the listen
//	aliases   through MailConfig, whose creations and deletions are outward actions (I-8) that Authorize runs, each
//	          created only if absent and carrying its use's effect_key (§15.8)
//	read      List and Read on every leg (mail_read.go)
//	status    GET /mail/status, this device's receiver, and whether a mail indexer stands, with §15.6's prompt
//	sends     Send (mail_send.go), CheckSend and SendResult (§14.5, §18.5; QD-1122), and the component's mail_send from
//	          the member's or/ (mail_send_result.go)
//
// Nothing here logs an address, an alias or a label (I-13), and no credential leaves through Read or Status (I-7).
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The mail component's name, its keychain namespace and its sealed directory (§5.4, §5.9).
const mailComponentName = "mail"

// The sealed directory's file that says mail is on for this device's network.
const mailEnabledFileName = "enabled.json"

// §15.6's prompt, which `ur status` and the apps show until a mail indexer stands: §15.9's and §18.5's foreground-only
// copy too (MailCoverageForegroundOnlyCopy), one text. Product copy, so a fixed text.
const MailIndexerPrompt = "A phone alone cannot reliably receive mail: an indexer, an always-on device (a desktop ur daemon, a NAS or VPS), is needed; time-sensitive codes may not arrive"

var (
	// No EvsClient, or no engine with a verified state, is there to work on yet.
	ErrMailUnbound = errors.New("mail: nothing to work on yet")
	// This device's member has no mailbox, or this device is a tagged sidecar, which has none of its own.
	ErrMailNoMailbox = errors.New("mail: no mailbox here")
	// The network has no mailcfg yet: mail is not enabled.
	ErrMailNoConfig = errors.New("mail: the network has no mailcfg")
	// What a call was given is out of shape. Names no address.
	ErrMailClientInvalid = errors.New("mail: invalid")
)

// POST /mail/enable, GET /mail/status and GET /sidecar/limits, which *SidecarApi answers.
type MailApi interface {
	MailEnable(ctx context.Context) (*MailEnabled, error)
	MailStatus(ctx context.Context) (*MailNetworkStatus, error)
	Limits(ctx context.Context) (*QuotaLimits, error)
}

// What a MailClient works on. A nil field leaves what it serves refused.
type MailBinding struct {
	// The network's EvsClient.
	Evs *EvsClient
	// §8's verified state, through the device's own engine.
	Engine *AclEngine
	// The core's poster of RepoCreate, RepoAdmin and RepoGrant (EvsClientArgs.FileStatement).
	FileStatement EvsFileStatementFunction
	// Whether this device holds a repo's key.
	Gkm GkmClient
	// The network's row under its root, read at each use: its label spells addresses.
	Network func() NetworkLabelRow
	// §5.4's gate, which *Sidecar is.
	Gate MailConfigGate
	// The mail routes, which *SidecarApi answers.
	Api MailApi
	// Whether a mail indexer stands for the network (§7.9's IndexerSet for mail, §15.6); nil reads unknown.
	MailIndexer func() (bool, error)
	// §7.9's verified config, which the designations and team_mail are read from (mail_indexer.go); nil leaves the
	// designations unknown, so nothing gates on them or alarms over them.
	Config func() (*ConfigState, error)
	// Opens a designation's sealed services; nil opens none, so the designations are unknown (mail_indexer.go).
	IndexerServices MailIndexerServices
	// The network's Team scopes in the verified state (mail_scope.go); nil knows none, so every scope deposit alarms.
	Scopes MailScopeSource
	// Raises an event on the Sidecar, mail_receiver_alarm's; nil only logs it.
	Event func(event SidecarEvent)
	// What SetReceiverEnabled files a designation through, and the config generation's key its services are sealed
	// to (mail_host.go); nil refuses it, and a nil key refuses the designation itself.
	Designator MailIndexerDesignator
	ConfigKey  func(ctx context.Context) (*EvsRepoKey, error)
	// The labels directly under the network's apex it publishes a host at, which a burner label must not shadow
	// (mail_burner_labels.go); nil for none.
	PublishedHosts func() []string
	// This device's identity key's signature over an outbox entry (Sidecar.Sign): nil queues no internet mail, its
	// recipients answered failed (mail_outbox.go).
	Sign func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error)
	// The network's §21.7 standing (GET /abuse/status), read before internet mail is queued; nil queues none.
	Standing func(ctx context.Context) (*AbuseStatus, error)
	// Whether a run read untrusted content or lost hook coverage (Sidecar.RunTainted, I-9): its sends each take the
	// gate, records approving none. Nil reads every run untainted, as a host that runs no agents binds.
	RunTainted func(runId Id) bool
	// P, for re-verifying an approved recipient's record at each use (mail_approved.go): nil approves no record. A running
	// daemon binds none until its approval gate's state source is installed (MCP-M3-06), so none approves there yet.
	SpendState func() (SpendState, error)
	// Retires a burner's DKIM selector at its burn (SmtpDkimKeys.Retire, MAIL-M9-03): nil retires nothing here, and
	// the device that published the selector retires its own once it reads the burn.
	BurnerSelectors MailBurnerSelectors
	// §5.4's search, which *Sidecar answers on its installed engine (Sidecar.Search): nil searches nothing, so a mail
	// search and IMAP's text terms answer unavailable (mail_search.go).
	Search func(ctx context.Context, request *SearchRequest) (*SearchStream, error)
	// The sender this host sends the member's internet mail with (§14's SmtpSender, a host's composition of it), whose
	// Check prices a send at this host's own cap and measure where it proves (CheckSend). Nil, as on a phone or any
	// host that composes no sender: CheckSend checks through the member's p/ records instead (mail_send_result.go).
	Sender MailSendChecker
}

// What checks the message a send would make, per recipient domain (§14.5's Check): SmtpSender is one.
type MailSendChecker interface {
	Check(ctx context.Context, message *SmtpOutboundMessage) (*SmtpSendCheck, error)
}

// A replying burner's selectors on this device (§15.9, D-DNS-11): SmtpDkimKeys is one.
type MailBurnerSelectors interface {
	// Retires this device's selectors for domain, a burner's <blabel>.<net>.<root>, through POST /smtp/dkim-keys,
	// whose server write deletes the label's copies with its last selector. No selector is no error.
	Retire(ctx context.Context, domain string) error
}

// How a MailClient reaches a repo's parts: over the bound EvsClient, or a test's stand-ins.
type mailClientParts interface {
	store(repoId Id) mailStore
	config(repoId Id, args *MailConfigArgs) (*MailConfig, error)
	repos(args *MailReposArgs) *MailRepos
	ingestor(repoId Id, args *MailIngestArgs) (*MailIngestor, error)
}

// The parts over an EvsClient.
type mailEvsClientParts struct {
	evs      *EvsClient
	settings *MailSettings
}

// The repo's file-mode ref by path.
func (self *mailEvsClientParts) store(repoId Id) mailStore {
	return newMailEvsStore(self.evs.Repo(repoId), nil, self.settings.Store)
}

// A MailConfig following the repo.
func (self *mailEvsClientParts) config(repoId Id, args *MailConfigArgs) (*MailConfig, error) {
	args.Repo = self.evs.Repo(repoId)
	return NewMailConfig(args)
}

// The network's MailRepos.
func (self *mailEvsClientParts) repos(args *MailReposArgs) *MailRepos {
	args.Evs = self.evs
	return newMailRepos(self.evs, args)
}

// The repo's ingestor.
func (self *mailEvsClientParts) ingestor(repoId Id, args *MailIngestArgs) (*MailIngestor, error) {
	args.Repo = self.evs.Repo(repoId)
	return NewMailIngestor(args)
}

// What this device's receiver says of itself, as the component last saw it.
type MailClientReceiverStatus struct {
	// This device runs a receiver: policy grants it the listen, and its settings say receive.
	Running bool
	// A registration is held, and a key is live so it serves.
	Listening bool
	Serving   bool
	// The listen waits on this approval (§5.4), nil when it does not.
	ApprovalId *Id
	// Why the receiver does not run or serve, empty when it does. Names no host or key (I-13).
	Problem string
}

// What MailClient.Status answers.
type MailClientStatus struct {
	// Mail is on for the network: this device enabled it, or GET /mail/status says so.
	Enabled bool
	// GET /mail/status's answer, nil where it could not be read.
	Network *MailNetworkStatus
	// This device's receiver.
	Receiver MailClientReceiverStatus
	// Whether a mail indexer stands for the network, and whether that could be told at all.
	MailIndexer      bool
	MailIndexerKnown bool
	// §15.6's prompt while mail is on and no mail indexer stands; empty once one does, or where that cannot be told.
	Prompt string
}

// What NewMailClient builds on.
type MailClientArgs struct {
	NetworkId Id
	SidecarId Id
	// The mail component's sealed directory: whether mail is on, the receiver's TLSA times and spool, and IMAP's
	// UIDs.
	Store SidecarStore
	// The mail component's keychain namespace: the local credential's verifier (mail_local_credential.go). Nil leaves
	// IMAP and submission with no credential to match.
	Secrets SidecarSecrets
	// Nil takes DefaultMailSettings.
	Settings *MailSettings
	// Nil is real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
}

// The mail on one device for one network. See the file header.
type MailClient struct {
	networkId Id
	sidecarId Id
	store     SidecarStore
	secrets   SidecarSecrets
	settings  *MailSettings
	clock     Clock
	log       Logger
	// the Sidecar the component binds from, nil for a client a host binds itself
	sidecar *Sidecar
	// rises at each message this device's ingest writes: IDLE's hint (mail_imap.go)
	imapHints *MonitorValue[uint64]

	stateLock sync.Mutex
	binding   *MailBinding
	// a test's stand-ins, else the bound EvsClient's
	partsOverride mailClientParts
	// built over the binding, dropped when it changes
	repos        *MailRepos
	config       *MailConfig
	configRepoId Id
	views        map[Id]*MailView
	// the search join of each mailbox's view, built at first use and made again when its view is (mail_search.go)
	searchJoins map[Id]*MailSearchJoin
	// the mailbox's store as IMAP sees it, by mailbox, built at first use over the binding (mail_imap_store.go)
	imapStores map[Id]*MailImapStore
	// the member's vault, by mailbox, built at first use over the binding (mail_codes.go)
	vaults map[Id]*MailVault
	// whether mail is on: this device's enable, kept in the store, or the network's status as last read
	enabledLoaded  bool
	enabledLocally bool
	enabledNetwork bool
	receiverStatus MailClientReceiverStatus
	// an app host's app is in the background, where a foreground-only host registers no listener (mail_host.go)
	background bool
	// the zone's row as the component last read it, which Network answers where the Sidecar binds
	zoneRow NetworkLabelRow
	// closed and replaced at each change the component looks at
	changed chan struct{}
	closed  bool
	// the component's running generation and a test's seams, on the legs that run a component (mail_component.go)
	componentRun   any
	componentSeams any
	// the gate kind mail's Lookup is registered on, and what removes it (mail_outbox.go)
	outboxLookupGate   MailConfigGate
	outboxLookupRemove func()
	// the send watch, which raises mail_send from the member's or/, on the legs that run a component
	// (mail_send_result.go)
	sendWatch any
}

// A client over args, bound to nothing yet.
func NewMailClient(args *MailClientArgs) (*MailClient, error) {
	if args == nil || args.Store == nil {
		return nil, fmt.Errorf("%w: a mail client needs its store", ErrMailClientInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailSettings()
	}
	if !settings.valid() {
		return nil, fmt.Errorf("%w: settings out of range", ErrMailClientInvalid)
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &MailClient{
		networkId:  args.NetworkId,
		sidecarId:  args.SidecarId,
		store:      args.Store,
		secrets:    args.Secrets,
		settings:   settings,
		clock:      clockOrReal(args.Clock),
		log:        log,
		imapHints:  NewMonitorValue(uint64(0)),
		views:      map[Id]*MailView{},
		imapStores: map[Id]*MailImapStore{},
		vaults:     map[Id]*MailVault{},
		changed:    make(chan struct{}),
	}, nil
}

// This Sidecar's mail, made at the first call on DefaultMailSettings. ErrSidecarStoreLocked before the network is
// known, and ErrSidecarNoIdentity before an identity.
func (self *Sidecar) Mail() (*MailClient, error) {
	return self.MailWith(nil)
}

// This Sidecar's mail, made at the first call on settings, nil taking the defaults; a later call answers the one
// made, whatever settings it names.
func (self *Sidecar) MailWith(settings *MailSettings) (*MailClient, error) {
	if held, ok := self.mail.Load().(*MailClient); ok {
		return held, nil
	}
	networkId := self.knownNetworkId()
	if self.instance == nil || networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	identity := self.Identity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	store, err := self.LocalStore().Directory(mailComponentName, mailComponentName)
	if err != nil {
		return nil, err
	}
	client, err := NewMailClient(&MailClientArgs{
		NetworkId: *networkId,
		SidecarId: identity.SidecarId,
		Store:     store,
		Secrets:   self.instance.secrets(*networkId, mailComponentName),
		Settings:  settings,
		Clock:     self.settings.ClockOrReal(),
		Log:       self.log,
	})
	if err != nil {
		return nil, err
	}
	client.sidecar = self
	if !self.mail.CompareAndSwap(nil, client) {
		return self.mail.Load().(*MailClient), nil
	}
	return client, nil
}

// Binds what the client works on, replacing what was bound; what was built over the old binding is dropped and built
// again at its next use. The component calls it as the Sidecar's pieces stand; a host may call it itself.
func (self *MailClient) Bind(binding *MailBinding) {
	if binding == nil {
		return
	}
	copied := *binding
	var closeConfig *MailConfig
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.binding != nil && self.binding.Evs == copied.Evs && self.binding.Engine == copied.Engine {
			// the same repos and state: keep what is built, take the rest
			self.binding = &copied
			return
		}
		self.binding = &copied
		self.repos = nil
		closeConfig = self.config
		self.config = nil
		self.configRepoId = Id{}
		self.views = map[Id]*MailView{}
		self.searchJoins = nil
		self.imapStores = map[Id]*MailImapStore{}
		self.vaults = map[Id]*MailVault{}
		self.notifyWithLock()
	}()
	if closeConfig != nil {
		closeConfig.Close()
	}
	if copied.Gate != nil {
		// so a restart reconciles a reserved send with no caller alive
		self.registerOutboxLookup(copied.Gate)
	}
}

// Wakes whoever waits on a change.
func (self *MailClient) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// The binding and the parts over it, or ErrMailUnbound with no EvsClient or engine.
func (self *MailClient) bound() (*MailBinding, mailClientParts, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.binding == nil || self.binding.Engine == nil || (self.binding.Evs == nil && self.partsOverride == nil) {
		return nil, nil, ErrMailUnbound
	}
	parts := self.partsOverride
	if parts == nil {
		parts = &mailEvsClientParts{evs: self.binding.Evs, settings: self.settings}
	}
	return self.binding, parts, nil
}

// The newest verified state, or ErrMailUnbound.
func (self *MailClient) state() (*MailBinding, mailClientParts, *AclState, error) {
	binding, parts, err := self.bound()
	if err != nil {
		return nil, nil, nil, err
	}
	state := binding.Engine.State()
	if state == nil {
		return nil, nil, nil, ErrMailUnbound
	}
	return binding, parts, state, nil
}

// The member whose mailbox this device works on: an untagged device's own member. False for a tagged sidecar, or
// one the state does not hold.
func mailMemberOf(state *AclState, sidecarId Id) (Id, bool) {
	sidecar := state.sidecarState(sidecarId)
	if sidecar == nil || !sidecar.valid || sidecar.tagged {
		return Id{}, false
	}
	return sidecar.memberId, true
}

// The network's MailRepos over the binding, built once a binding.
func (self *MailClient) mailRepos() (*MailRepos, *AclState, error) {
	binding, parts, state, err := self.state()
	if err != nil {
		return nil, nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.repos == nil {
		engine := binding.Engine
		self.repos = parts.repos(&MailReposArgs{
			State:         engine.State,
			FileStatement: binding.FileStatement,
			Gkm:           binding.Gkm,
			SidecarId:     self.sidecarId,
			Log:           self.log,
		})
	}
	return self.repos, state, nil
}

// This device's member's mailbox, or ErrMailNoMailbox.
func (self *MailClient) mailboxId() (Id, error) {
	repos, state, err := self.mailRepos()
	if err != nil {
		return Id{}, err
	}
	memberId, ok := mailMemberOf(state, self.sidecarId)
	if !ok {
		return Id{}, ErrMailNoMailbox
	}
	mailboxId, ok := repos.Mailbox(memberId)
	if !ok {
		return Id{}, ErrMailNoMailbox
	}
	return mailboxId, nil
}

// The network's MailConfig, built over its mailcfg repo once that stands, or ErrMailNoConfig.
func (self *MailClient) mailConfig() (*MailConfig, error) {
	repos, _, err := self.mailRepos()
	if err != nil {
		return nil, err
	}
	repoId, ok := repos.MailConfigRepo()
	if !ok {
		return nil, ErrMailNoConfig
	}
	binding, parts, err := self.bound()
	if err != nil {
		return nil, err
	}
	held := func() *MailConfig {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.config != nil && self.configRepoId == repoId {
			return self.config
		}
		return nil
	}()
	if held != nil {
		return held, nil
	}
	config, err := parts.config(repoId, &MailConfigArgs{
		Network:   binding.Network,
		SidecarId: self.sidecarId,
		Authority: &MailConfigAclAuthority{Engine: binding.Engine},
		Gate:      binding.Gate,
		Alarm: func(alarm *MailConfigAlarm) {
			self.raiseReceiverAlarm(SidecarMailReceiverAlarmRecord, alarm.SidecarId, alarm.RepoId)
		},
		BurnerLabels: self.burnerLabels(),
		Clock:        self.clock,
		Log:          self.log,
		Settings:     self.settings.Config,
	})
	if err != nil {
		return nil, err
	}
	var replaced *MailConfig
	winner := func() *MailConfig {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.config != nil && self.configRepoId == repoId {
			return self.config
		}
		replaced = self.config
		self.config = config
		self.configRepoId = repoId
		return config
	}()
	if winner != config {
		config.Close()
	}
	if replaced != nil {
		replaced.Close()
	}
	return winner, nil
}

// The network's MailConfig synced at least once.
func (self *MailClient) syncedConfig(ctx context.Context) (*MailConfig, error) {
	config, err := self.mailConfig()
	if err != nil {
		return nil, err
	}
	if _, err := config.Addresses(); errors.Is(err, ErrMailConfigNotSynced) {
		if err := config.Sync(ctx); err != nil {
			return nil, err
		}
	}
	return config, nil
}

// Whether mail is on: this device enabled it, or the network's status last said so.
func (self *MailClient) Enabled() bool {
	self.loadEnabled()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.enabledLocally || self.enabledNetwork
}

// The store's word on this device's enable, read once.
func (self *MailClient) loadEnabled() {
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.enabledLoaded
	}()
	if loaded {
		return
	}
	enabled := false
	if reader, err := self.store.Open(mailEnabledFileName); err == nil {
		data, readErr := io.ReadAll(reader)
		reader.Close()
		record := struct {
			EnabledTimeMillis int64 `json:"enabled_time_ms"`
		}{}
		enabled = readErr == nil && json.Unmarshal(data, &record) == nil && 0 < record.EnabledTimeMillis
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.enabledLoaded {
		self.enabledLoaded = true
		self.enabledLocally = self.enabledLocally || enabled
	}
}

// Keeps this device's enable at enabledTime, durably, and wakes the component.
func (self *MailClient) setEnabledLocally(enabledTime time.Time) error {
	data, err := json.Marshal(struct {
		EnabledTimeMillis int64 `json:"enabled_time_ms"`
	}{EnabledTimeMillis: enabledTime.UnixMilli()})
	if err != nil {
		return err
	}
	writer, err := self.store.Create(mailEnabledFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.enabledLoaded = true
	if !self.enabledLocally {
		self.enabledLocally = true
		self.notifyWithLock()
	}
	return nil
}

// Takes the network's status as read, waking the component when it turns mail on or off.
func (self *MailClient) setNetworkEnabled(enabled bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.enabledNetwork != enabled {
		self.enabledNetwork = enabled
		self.notifyWithLock()
	}
}

// Turns mail on for the network (see the file header's enable row): mailcfg, the member's mailbox and this device's
// RepoAdmin of it, then POST /mail/enable. A step that cannot land refuses with its own error, and each resumes on the
// next call: a creation is taken up again under its id, never filed twice (MailRepos).
func (self *MailClient) Enable(ctx context.Context) (*MailEnabled, error) {
	binding, _, err := self.bound()
	if err != nil {
		return nil, err
	}
	if binding.Api == nil {
		return nil, fmt.Errorf("%w: no api to enable through", ErrMailUnbound)
	}
	repos, state, err := self.mailRepos()
	if err != nil {
		return nil, err
	}
	if _, ok := repos.MailConfigRepo(); !ok {
		if _, err := repos.EnsureMailConfig(ctx); err != nil {
			return nil, err
		}
	}
	memberId, ok := mailMemberOf(state, self.sidecarId)
	if !ok {
		return nil, ErrMailNoMailbox
	}
	mailbox, err := repos.EnsureMailbox(ctx, memberId)
	if err != nil {
		return nil, err
	}
	if _, err := repos.EnsureRepoAdmin(ctx, mailbox.RepoId()); err != nil {
		return nil, err
	}
	enabled, err := binding.Api.MailEnable(ctx)
	if err != nil {
		return nil, err
	}
	if err := self.setEnabledLocally(enabled.EnabledTime); err != nil {
		return nil, err
	}
	return enabled, nil
}

// Every address record a reader honors (mail_aliases, `ur id ls`), each Known only while policy grants its creator.
func (self *MailClient) Aliases(ctx context.Context) ([]*MailAddressLookup, error) {
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return nil, err
	}
	return config.Addresses()
}

// The verified group inboxes for the MCP recipient guard. An unreadable record leaves a general repo unclassified.
func (self *Sidecar) MailGroupInboxes(ctx context.Context) (map[Id]bool, error) {
	mail, err := self.Mail()
	if err != nil {
		return nil, err
	}
	binding, _, state, err := mail.state()
	if err != nil {
		return nil, err
	}
	follower := self.ConfigFollower()
	if follower == nil {
		return nil, ErrMailConfigNotSynced
	}
	engine, _ := follower.StandingPolicy()
	if engine != binding.Engine {
		return nil, ErrMailConfigNotSynced
	}
	for _, repo := range state.Rows().GetRepos() {
		if repo.GetKind() == protocol.RepoKind_REPO_KIND_MAILCFG && mailRepoStands(repo) && !mailRepoNetworkConfig(repo) {
			// The network mailcfg alone cannot rule out a group in a Team scope's mailcfg.
			return nil, ErrMailConfigNotSynced
		}
	}
	config, err := mail.mailConfig()
	if err != nil {
		return nil, err
	}
	if err := config.Sync(ctx); err != nil {
		return nil, err
	}
	groups, err := config.groupInboxes()
	if err != nil {
		return nil, err
	}
	standing, _ := follower.StandingPolicy()
	if standing != engine || engine.State() != state {
		return nil, ErrMailConfigNotSynced
	}
	mail.stateLock.Lock()
	defer mail.stateLock.Unlock()
	if mail.binding != binding || mail.config != config {
		return nil, ErrMailConfigNotSynced
	}
	return groups, nil
}

// What CreateAlias creates.
type MailAliasCreateArgs struct {
	// <LocalPart>@<net>.<root>.
	LocalPart string
	// A group address this mailcfg holds, whose repo the alias delivers to, for mail_alias_create's group; empty
	// delivers to this device's member's mailbox.
	Group string
	// What the outward action carries to the gate (I-8).
	Action MailConfigActionArgs
}

// An id or a group alias (`ur id create`, mail_alias_create): an outward action, which Authorize runs once its use is
// reserved and which may answer *ApprovalPendingError, created only if absent (§15.8).
func (self *MailClient) CreateAlias(ctx context.Context, args *MailAliasCreateArgs) (*MailAddressLookup, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no alias", ErrMailClientInvalid)
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return nil, err
	}
	create := &MailCreateAddressArgs{LocalPart: args.LocalPart, Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, Action: args.Action}
	if args.Group != "" {
		create.Group = args.Group
	} else {
		mailboxId, err := self.mailboxId()
		if err != nil {
			return nil, err
		}
		create.MailboxRepoId = mailboxId
	}
	return config.CreateAddress(ctx, create)
}

// Deletes an alias (`ur id rm`, mail_alias_delete), an outward action as its creation is.
func (self *MailClient) DeleteAlias(ctx context.Context, localPart string, action MailConfigActionArgs) error {
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return err
	}
	return config.DeleteAddress(ctx, &MailDeleteAddressArgs{LocalPart: localPart, Action: action})
}

// What CreateAgentAddress creates.
type MailAgentAddressArgs struct {
	// The agent's name, the address's local part: <agent>@<net>.<root>.
	Agent string
	// The member who sponsors the agent, whose mailbox the address delivers to (§15.8's agent row).
	SponsorMemberId Id
	Action          MailConfigActionArgs
}

// An agent's address, made at its registration in its sponsor's mailbox ([R:product] §2.2 N2): an outward action as
// an alias is.
func (self *MailClient) CreateAgentAddress(ctx context.Context, args *MailAgentAddressArgs) (*MailAddressLookup, error) {
	if args == nil || args.SponsorMemberId == (Id{}) {
		return nil, fmt.Errorf("%w: no agent or sponsor", ErrMailClientInvalid)
	}
	repos, _, err := self.mailRepos()
	if err != nil {
		return nil, err
	}
	mailboxId, ok := repos.Mailbox(args.SponsorMemberId)
	if !ok {
		return nil, ErrMailNoMailbox
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return nil, err
	}
	return config.CreateAddress(ctx, &MailCreateAddressArgs{
		LocalPart:     args.Agent,
		Kind:          protocol.MailAddressKind_MAIL_ADDRESS_AGENT,
		MailboxRepoId: mailboxId,
		Action:        args.Action,
	})
}

// A group address and its repo (`ur id group-create`): MailRepos.CreateGroup, which refuses until RepoCreate carries
// plan-MAIL-group-inbox's marker.
func (self *MailClient) CreateGroup(ctx context.Context, args *MailCreateGroupArgs) (*EvsRepo, error) {
	repos, _, err := self.mailRepos()
	if err != nil {
		return nil, err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return nil, err
	}
	return repos.CreateGroup(ctx, config, args)
}

// A member joined to a group (`ur id group-add`, the only way in, §16.11): the mailcfg record and the RepoGrant.
func (self *MailClient) AddGroupMember(ctx context.Context, group string, memberId Id) error {
	repos, _, err := self.mailRepos()
	if err != nil {
		return err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return err
	}
	return repos.AddGroupMember(ctx, config, group, memberId)
}

// The zone's row as the component last read it.
func (self *MailClient) networkRow() NetworkLabelRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.zoneRow
}

// Keeps the zone's row the component read.
func (self *MailClient) setNetworkRow(row NetworkLabelRow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.zoneRow = row
}

// Takes what the component last saw of this device's receiver.
func (self *MailClient) setReceiverStatus(status MailClientReceiverStatus) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.receiverStatus = status
}

// Mail's status for `ur mail status`, `ur status` and the apps: see the file header's status row. A part that could
// not be read is left unknown, never guessed.
func (self *MailClient) Status(ctx context.Context) (*MailClientStatus, error) {
	status := &MailClientStatus{}
	binding := func() *MailBinding {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		status.Receiver = self.receiverStatus
		return self.binding
	}()
	if binding != nil && binding.Api != nil {
		if network, err := binding.Api.MailStatus(ctx); err == nil {
			status.Network = network
			self.setNetworkEnabled(network.Enabled)
		}
	}
	if binding != nil && binding.MailIndexer != nil {
		if standing, err := binding.MailIndexer(); err == nil {
			status.MailIndexer = standing
			status.MailIndexerKnown = true
		}
	}
	status.Enabled = self.Enabled()
	// the prompt stands while no mail indexer is known to stand; where that cannot be told it is left out, never
	// shown over an indexer that may stand
	if status.Enabled && status.MailIndexerKnown && !status.MailIndexer {
		status.Prompt = MailIndexerPrompt
	}
	return status, nil
}

// The check of the message Send would make of args (§14.5's Check, §18.5's CheckSend; QD-1122): per recipient domain
// of its internet recipients, in the order each first appears, its mode, the message's encoded bytes, the DATA cap, the
// expected delay and ok, too_large or unknown. The bound sender (MailBinding.Sender) checks it at this host's own cap
// where it proves; a host with none checks through the member's p/ records, as a phone prices a send on its prover
// hosts' (mail_send_result.go). It signs, keeps, deposits and queues nothing and asks no gate, so an app may call it on
// each change of a draft; a draft Send would refuse is refused alike, and mail to the network's own addresses alone
// answers no domain, since none of it goes through §14. ErrMailSendUnavailable on the page Worker's leg, which sends
// no mail.
func (self *MailClient) CheckSend(ctx context.Context, args *MailSendArgs) (*SmtpSendCheck, error) {
	return self.checkSend(ctx, args)
}

// The outcomes of the send sendId names (§14.5's outcomes, §18.5's GetSendResult; QD-1122), per recipient domain as the
// member's or/ holds them, found by the send_id its record names, so every device of the member answers alike, after
// the send's o/ entry is gone too. A send still in o/ that no prover host has written outcomes for answers queued at
// each of its domains (mail_send_result.go). ErrMailSendUnknown where the member's mailbox holds neither, as for mail
// to the network's own addresses alone, which queues nothing; ErrMailSendUnavailable on the page Worker's leg.
func (self *MailClient) SendResult(ctx context.Context, sendId Id) (*SmtpSendResult, error) {
	return self.sendResult(ctx, sendId)
}

// Ends what the client built: mailcfg's follower. The component's Close calls it.
func (self *MailClient) closeParts() {
	config := func() *MailConfig {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		config := self.config
		self.config = nil
		self.repos = nil
		self.views = map[Id]*MailView{}
		self.searchJoins = nil
		self.imapStores = map[Id]*MailImapStore{}
		self.vaults = map[Id]*MailVault{}
		self.notifyWithLock()
		return config
	}()
	if config != nil {
		config.Close()
	}
	remove := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		remove := self.outboxLookupRemove
		self.outboxLookupGate, self.outboxLookupRemove = nil, nil
		return remove
	}()
	if remove != nil {
		remove()
	}
}
