//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// M8's mail rows of §22 on T2 (MAIL-M8-10; R-MAIL-6, R-MAIL-8, D-MAIL-15, FS-36, FS-82, R-PHASE-7; owner decisions 12,
// 88, 150, 197): the release-readiness paths BS1 ships on, composed from what MAIL-M8-01 to MAIL-M8-09 landed and adding
// no mechanism. Release readiness is never a per-user gate (owner decision 12): coverage shows copy and refuses nothing.
// No app is a mail indexer (owner decision 197), so the plan's Android path is the act row's refusal.
//
//	indexer paths  a desktop ur daemon, a NAS and a VPS: each is one mechanism, a ur daemon, so each path is the same
//	               run under its host's name. Before a designation an online receiver still takes mail, coverage reads
//	               foreground-only and Status, which ur status and mail.status print, carries §15.6's prompt (FS-82's
//	               M8 case); the device's IndexerSet for mail lands, coverage reads indexer and the prompt is gone; and
//	               the designated receiver takes the next message through the router, deposited under its own identity
//	act            SetReceiverEnabled on a real ur daemon's Sidecar, in a real Daemon of the admission suite's world
//	               (Fs98World), files its IndexerSet through the Sidecar's own act: once, a retry filing nothing, and
//	               false retires it; an MCP origin and an Android or iOS app host file nothing (owner decision 197)
//	copy           CreateBurner hands back §15.9's foreground-only copy before a first burner under none and
//	               foreground-only, and never under indexer or for a later burner, and refuses none of them
//	FS-36          the router's own miss, held (MAIL-M8-05's wake hold), wakes the lapsed receiver once and at once
//	               through SDK-M8-12's wake path, the waking hint writer, its enqueue and the push sender over the
//	               host's Redis, its payload a topic class and a version; the hold's next Find then takes the session.
//	               T2's one Redis node, not T3's 3-master cluster, which FS-36's row names
//
// The world (mailM8World): the network's §8 state is the admission suite's real log with ACL's own compile
// (AdmissionNet), every device's AclEngine holding its state and its head's local policy as AclFollower installs them;
// evs and gkm are mailworld's MailWorld, whose router, receiver session and engine S7 composes, lined up on the log's
// ids and keys, its mailcfg the network's; the receiver resolves recipients over its own MailConfig of that mailcfg,
// as mail_component_receive.go's resolver does; the owner's laptop runs a MailClient bound to the world as the
// component binds one, with its own stand-ins where no host has a part yet:
//
//	gate       §5.4's gate as another approval-capable device's decision leaves it: each outward action's effect run
//	           once under a use key drawn from its bytes (mailM8Gate). §16.6's real gate is the approval suite's
//	api        POST /mail/enable, GET /mail/status and GET /sidecar/limits as api answers them, each call counted
//	services   a designation's sealed services opened with the config's generation key under its statement's header,
//	           read from the log's entry at the designation's position: the component binds no opener, since
//	           ConfigIndexer does not carry the header (mail_component.go), so no running Sidecar reads indexer yet
//	indexer    Status's MailIndexer, the component's mailIndexerCovers, answered from ReceiverCoverage
//	resolver   FS-36's sidecar-to-client resolution, plan-KEYS-hint-addressing's, which no route serves yet
//	           (mailM8PushResolver)
//
// Every name and address is synthetic: .example names and RFC 5737 and 3849 addresses (connect/CODESTYLE.md's test
// data rule). Nothing sleeps: every wait is a monitor's, a pipe's or a timer the test saw armed.

package sidecartest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// The root the network's addresses are under, which the DNS harness serves, and a network's label by default.
const (
	mailM8Root  = "harness.example"
	mailM8Label = "lbl0000001"
)

// The sender of sign-up mail, RFC 5737's, and its domain.
var mailM8Sender = netip.MustParseAddr("198.51.100.44")

const mailM8SenderDomain = "shop.example"

// Members hold burners and receive: listen on every mail alias, so a member's records route (D-ACL-12), and on the
// receiver's socket, so a member's device may receive.
const mailM8PolicyReceive = `{"grants": [
	{"src": ["autogroup:member"], "dst": ["mail:*"], "allow": ["listen"]},
	{"src": ["autogroup:member"], "dst": ["sock:smtp/25/mx"], "allow": ["listen"]}
]}`

// Members hold burners, and no device may receive: coverage none.
const mailM8PolicyNoReceiver = `{"grants": [{"src": ["autogroup:member"], "dst": ["mail:*"], "allow": ["listen"]}]}`

// What a mailM8World is built with.
type mailM8WorldSettings struct {
	// The receiver's device by its host's name: "desktop daemon", "nas" or "vps".
	ReceiverName string
	// The network's policy document.
	Policy string
	// The network's label: mailM8Label when empty.
	Label string
	// The host the world's router, receiver and evs run on: the Net's fakes when nil, which a scenario's harness
	// captures; a test running several worlds on one Net gives each its own (NewFakeHost on the Net's clock).
	Host *sidecartest.FakeHost
	// Changes the MailWorld's settings once the world has set its own, such as the router's wake hold; nil none.
	MailWorld func(settings *mailworld.MailWorldSettings)
	// A network another world of the test already runs, an Fs98World's, whose owner's laptop the world takes; nil
	// bootstraps one on the Net's tier.
	Admission *sidecartest.AdmissionNet
}

// GET /sidecar/limits, GET /mail/status and POST /mail/enable as api answers them, counted. Safe for concurrent use.
type mailM8Api struct {
	clock sidecar.Clock

	stateLock sync.Mutex
	limits    map[string]int64
	calls     map[string]int
}

func newMailM8Api(clock sidecar.Clock) *mailM8Api {
	return &mailM8Api{
		clock: clock,
		limits: map[string]int64{
			"mail_inbound_message_bytes": 50 * 1024 * 1024, "mail_inbound_recipients": 100, "mail_inbound_repos_per_message": 8,
			"mail_burners_active": 50, "mail_burner_creates_per_day": 20,
		},
		calls: map[string]int{},
	}
}

func (self *mailM8Api) count(route string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls[route] += 1
}

func (self *mailM8Api) MailEnable(ctx context.Context) (*sidecar.MailEnabled, error) {
	self.count("POST /mail/enable")
	return &sidecar.MailEnabled{EnabledTime: self.clock.Now()}, nil
}

func (self *mailM8Api) MailStatus(ctx context.Context) (*sidecar.MailNetworkStatus, error) {
	self.count("GET /mail/status")
	return &sidecar.MailNetworkStatus{Enabled: true}, nil
}

func (self *mailM8Api) Limits(ctx context.Context) (*sidecar.QuotaLimits, error) {
	self.count("GET /sidecar/limits")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	limits := map[string]int64{}
	for key, value := range self.limits {
		limits[key] = value
	}
	return &sidecar.QuotaLimits{Tier: "pro", Limits: limits, Enforced: true}, nil
}

// Every route called, with how many times.
func (self *mailM8Api) Calls() map[string]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := map[string]int{}
	for route, count := range self.calls {
		calls[route] = count
	}
	return calls
}

// §5.4's gate as another approval-capable device's decision leaves it (the file header's gate row): each action's
// effect run once under a use key drawn from its bytes, a recorded outcome answered again for the same bytes, and each
// kind's Lookup kept. Safe for concurrent use.
type mailM8Gate struct {
	stateLock sync.Mutex
	lookups   map[sidecar.SidecarActionKind]sidecar.SidecarEffectLookup
	outcomes  map[string]*sidecar.SidecarOutcome
	actions   []*sidecar.SidecarAction
}

func newMailM8Gate() *mailM8Gate {
	return &mailM8Gate{lookups: map[sidecar.SidecarActionKind]sidecar.SidecarEffectLookup{}, outcomes: map[string]*sidecar.SidecarOutcome{}}
}

// The key of the use an action's bytes are spent under.
func mailM8EffectKey(canonical []byte) []byte {
	key := sha256.Sum256(append([]byte("mail m8 use of "), canonical...))
	return key[:]
}

func (self *mailM8Gate) Authorize(ctx context.Context, action *sidecar.SidecarAction, decision *bridge.Signed) error {
	recorded, err := func() (*sidecar.SidecarOutcome, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.actions = append(self.actions, action)
		if self.lookups[action.Kind] == nil {
			return nil, errors.New("a kind with no registered lookup is refused before its reserve")
		}
		if outcome := self.outcomes[string(action.Canonical)]; outcome != nil && outcome.State != sidecar.ApprovalOutcomeUncertain {
			return &sidecar.SidecarOutcome{State: outcome.State, EffectRef: bytes.Clone(outcome.EffectRef)}, nil
		}
		return nil, nil
	}()
	if err != nil {
		return err
	}
	if recorded != nil {
		action.Outcome = recorded
		return nil
	}
	effectRef, runErr := action.Effect.Run(ctx, mailM8EffectKey(action.Canonical))
	outcome := &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeUncertain, Err: runErr}
	switch {
	case runErr == nil:
		outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeDone, EffectRef: bytes.Clone(effectRef)}
	case errors.Is(runErr, sidecar.ErrSidecarEffectNotDone):
		outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeNotDone, Err: runErr}
	}
	self.stateLock.Lock()
	self.outcomes[string(action.Canonical)] = outcome
	self.stateLock.Unlock()
	action.Outcome = outcome
	return nil
}

func (self *mailM8Gate) RegisterEffectLookup(kind sidecar.SidecarActionKind, lookup sidecar.SidecarEffectLookup) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lookups[kind] = lookup
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.lookups, kind)
	}
}

// How many actions the gate was handed.
func (self *mailM8Gate) ActionCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.actions)
}

// The config repo's first generation key, which an IndexerSet's services are sealed to: a group on a fake gkm of its
// own, created by the owner's laptop, as a host's recovery reads the config's keys (fs98.go's config keys).
func mailM8ConfigKey(t testing.TB, admission *sidecartest.AdmissionNet) *sidecar.EvsRepoKey {
	t.Helper()
	clock := admission.Clock()
	owner := admission.Owner()
	gkm := sidecartest.NewFakeGkm(clock, sidecartest.NewFakeBlobs(clock, nil, nil, nil), nil)
	signer := &sidecartest.FakeGkmSigner{SidecarId: owner.SidecarId, PrivateKey: owner.Key}
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(owner.MemberId, owner.SidecarId)
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: admission.ConfigRepoId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG})
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{memberRow}
	view := sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{
		Rows:         rows,
		IdentityKeys: map[sidecar.Id][]byte{owner.SidecarId: signer.PublicKey()},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{admission.ConfigRepoId(): {owner.SidecarId}},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{admission.ConfigRepoId(): {owner.SidecarId}},
	})
	client := gkm.Client(owner.SidecarId, signer.Sign)
	client.AuthAdvanced(view)
	key, err := client.CreateGroup(admission.Context(), &sidecar.GkmCreateGroupArgs{
		NetworkId: admission.NetworkId(), RepoId: admission.ConfigRepoId(), Kind: protocol.RepoKind_REPO_KIND_CONFIG,
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A fake host of its own on net's clock, for one of several worlds a test runs on net.
func mailM8Host(t *testing.T, net *sidecartest.Net) *sidecartest.FakeHost {
	t.Helper()
	host := sidecartest.NewFakeHost(t.Context(), net.Clock(), nil, nil, nil)
	t.Cleanup(host.Redis.Close)
	return host
}

// One network with mail on (the file header's world).
type mailM8World struct {
	t         *testing.T
	ctx       context.Context
	net       *sidecartest.Net
	admission *sidecartest.AdmissionNet
	// The owner's laptop, the genesis device, consented and the network's config writer: the user's device.
	owner *sidecartest.AdmissionDevice
	// The device that runs the receiver, consented too, so its own act may designate it at member scope.
	receiver *sidecartest.AdmissionDevice

	label        string
	mailboxId    sidecar.Id
	mailConfigId sidecar.Id
	configKey    *sidecar.EvsRepoKey

	mail *mailworld.MailWorld
	api  *mailM8Api
	gate *mailM8Gate

	ownerEvs       *sidecar.EvsClient
	ownerEngine    *sidecar.AclEngine
	ownerMail      *sidecar.MailClient
	receiverEngine *sidecar.AclEngine
	receiverConfig *sidecar.MailConfig

	stateLock sync.Mutex
	// every other device's engine, which Install keeps at the tip too
	engines []*sidecar.AclEngine
}

// The world on net (the file header's world), settings nil taking a desktop daemon's receiver under
// mailM8PolicyReceive.
func newMailM8World(t *testing.T, net *sidecartest.Net, settings *mailM8WorldSettings) *mailM8World {
	t.Helper()
	if settings == nil {
		settings = &mailM8WorldSettings{}
	}
	if settings.ReceiverName == "" {
		settings.ReceiverName = "desktop daemon"
	}
	if settings.Policy == "" {
		settings.Policy = mailM8PolicyReceive
	}
	if settings.Label == "" {
		settings.Label = mailM8Label
	}
	admission := settings.Admission
	if admission == nil {
		tier, err := net.AdmissionTier()
		if err != nil {
			t.Fatal(err)
		}
		tier.AclCompile = sidecartest.AclAdmissionCompile
		admission = sidecartest.NewAdmissionNet(t, tier)
		t.Cleanup(admission.Close)
	}
	owner := admission.Owner()
	receiver := admission.Device(settings.ReceiverName, owner.MemberId)
	admission.AdmitDevice(owner, receiver, 0)
	// the member's laptop confirms its new device (§8.5's owner confirm), so a member-scope designation of it holds
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_OWNER_CONFIRM, admission.OwnerConfirm(receiver)))
	if !admission.Consented(receiver, owner.MemberId) {
		t.Fatalf("the %s is not consented", settings.ReceiverName)
	}
	self := &mailM8World{
		t:            t,
		ctx:          admission.Context(),
		net:          net,
		admission:    admission,
		owner:        owner,
		receiver:     receiver,
		label:        settings.Label,
		mailboxId:    admission.Id("mailbox"),
		mailConfigId: admission.Id("mailcfg"),
		api:          newMailM8Api(admission.Clock()),
		gate:         newMailM8Gate(),
	}
	// the member's mailbox, created by its consented laptop, and the network's mailcfg, by its config writer (§8.8)
	for _, created := range []struct {
		repoId sidecar.Id
		kind   protocol.RepoKind
	}{{repoId: self.mailboxId, kind: protocol.RepoKind_REPO_KIND_MAILBOX}, {repoId: self.mailConfigId, kind: protocol.RepoKind_REPO_KIND_MAILCFG}} {
		admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
			Header: admission.Header(), RepoId: created.repoId.Bytes(), Kind: created.kind,
		}))
	}
	admission.SaveAclPolicy([]byte(settings.Policy), sidecartest.AclSaveMembers{})
	self.configKey = mailM8ConfigKey(t, admission)

	mailSettings := mailworld.DefaultMailWorldSettings()
	mailSettings.Root = mailM8Root
	mailSettings.Label = settings.Label
	mailSettings.Addresses = nil
	mailSettings.NetworkId = admission.NetworkId()
	mailSettings.MemberId = owner.MemberId
	mailSettings.RepoId = self.mailboxId
	mailSettings.MailConfigRepoId = self.mailConfigId
	mailSettings.Owner = &sidecartest.FakeGkmSigner{SidecarId: owner.SidecarId, PrivateKey: owner.Key}
	mailSettings.Receiver = &sidecartest.FakeGkmSigner{SidecarId: receiver.SidecarId, PrivateKey: receiver.Key}
	mailSettings.Resolve = self.resolve
	if settings.MailWorld != nil {
		settings.MailWorld(mailSettings)
	}
	host := settings.Host
	if host == nil {
		host = net.Fakes()
	}
	self.mail = mailworld.NewMailWorld(t, host, net.Clock(), mailSettings)

	self.ownerEngine = sidecar.NewAclEngine(owner.SidecarId, nil, nil, nil)
	self.receiverEngine = sidecar.NewAclEngine(receiver.SidecarId, nil, nil, nil)
	self.Install()

	receiverEvs := self.mail.Device(self.mail.Receiver, false, sidecartest.NewFakeStore().Root(), nil)
	receiverConfig, err := sidecar.NewMailConfig(&sidecar.MailConfigArgs{
		Repo:      receiverEvs.Repo(self.mailConfigId),
		Network:   self.row,
		SidecarId: receiver.SidecarId,
		Authority: &sidecar.MailConfigAclAuthority{Engine: self.receiverEngine},
		Clock:     net.Clock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiverConfig.Close)
	self.receiverConfig = receiverConfig

	self.ownerEvs = self.mail.Device(self.mail.Owner, false, sidecartest.NewFakeStore().Root(), nil)
	self.ownerMail = self.mailClient(owner.SidecarId, self.ownerEvs, self.ownerEngine, nil, nil)
	return self
}

// A MailClient of sidecarId bound to the world as the component binds one (the file header's world): evs over evs,
// §8 through engine, the network's state, the gate, the api and the stand-ins for its services opener and its
// indexer answer; designator files its designations, configKey nil taking the world's. settings nil is the daemon's.
func (self *mailM8World) mailClient(sidecarId sidecar.Id, evs *sidecar.EvsClient, engine *sidecar.AclEngine, designator sidecar.MailIndexerDesignator, settings *sidecar.MailSettings) *sidecar.MailClient {
	self.t.Helper()
	client, err := sidecar.NewMailClient(&sidecar.MailClientArgs{
		NetworkId: self.admission.NetworkId(),
		SidecarId: sidecarId,
		Store:     sidecartest.NewFakeStore().Root(),
		Settings:  settings,
		Clock:     self.net.Clock(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	client.Bind(&sidecar.MailBinding{
		Evs:             evs,
		Engine:          engine,
		Network:         self.row,
		Gate:            self.gate,
		Api:             self.api,
		Config:          self.config,
		IndexerServices: self.openServices,
		MailIndexer: func() (bool, error) {
			coverage, err := client.ReceiverCoverage(self.ctx)
			return coverage == sidecar.MailCoverageIndexer, err
		},
		Designator: designator,
		ConfigKey: func(ctx context.Context) (*sidecar.EvsRepoKey, error) {
			return self.configKey, nil
		},
	})
	return client
}

// The network's row under its root.
func (self *mailM8World) row() sidecar.NetworkLabelRow {
	return sidecar.NetworkLabelRow{Root: mailM8Root, NetworkId: self.admission.NetworkId(), Label: self.label}
}

// The network's verified state at the tip, every device's.
func (self *mailM8World) config() (*sidecar.ConfigState, error) {
	return self.admission.State(), nil
}

// Installs the tip's acl state and its config head's local policy in every device's engine, as each device's
// AclFollower does once its ConfigClient applied the tip (acl_follow.go's apply and compileLocal).
func (self *mailM8World) Install() {
	self.t.Helper()
	state := self.admission.State()
	acl, err := state.Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	base := state.Base()
	head, err := self.admission.Heads().ReadConfigHead(self.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		self.t.Fatal(err)
	}
	input, err := sidecar.NewAclCompileInput(head, sidecar.ConfigCompileRowsOf(state))
	if err != nil {
		self.t.Fatal(err)
	}
	local, err := sidecar.CompileAclLocal(input)
	if err != nil {
		self.t.Fatal(err)
	}
	engines := func() []*sidecar.AclEngine {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return append([]*sidecar.AclEngine{self.ownerEngine, self.receiverEngine}, self.engines...)
	}()
	for _, engine := range engines {
		if err := engine.Install(acl, local); err != nil {
			self.t.Fatal(err)
		}
	}
}

// An engine of another device, which Install keeps at the tip with the rest.
func (self *mailM8World) Engine(sidecarId sidecar.Id) *sidecar.AclEngine {
	self.t.Helper()
	engine := sidecar.NewAclEngine(sidecarId, nil, nil, nil)
	self.stateLock.Lock()
	self.engines = append(self.engines, engine)
	self.stateLock.Unlock()
	self.Install()
	return engine
}

// The receiver's resolver, as mail_component_receive.go's: a recipient parsed under the root, then the receiver's
// own MailConfig, an unparsable one unknown.
func (self *mailM8World) resolve(ctx context.Context, address string) (*sidecar.MailSessionRecipient, error) {
	recipient, err := sidecar.ParseMailRecipient(mailM8Root, address)
	if err != nil {
		return &sidecar.MailSessionRecipient{}, nil
	}
	lookup, err := self.receiverConfig.Resolve(ctx, recipient)
	if err != nil {
		return nil, err
	}
	return &sidecar.MailSessionRecipient{Known: lookup.Known, Address: recipient.Address(), RepoId: lookup.MailboxRepoId}, nil
}

// The receiver's mailcfg read again, as an evs hint of mailcfg's change has the receiver's follower do.
func (self *mailM8World) SyncReceiver() {
	self.t.Helper()
	if err := self.receiverConfig.Sync(self.ctx); err != nil {
		self.t.Fatal(err)
	}
}

// The config generation's key, for the generation it is.
func (self *mailM8World) configKeyAt(generation uint64) *sidecar.EvsRepoKey {
	if self.configKey == nil || self.configKey.Generation() != generation {
		return nil
	}
	return self.configKey
}

// A designation's sealed services, opened with the config's generation key under the header of the statement at its
// position in the log (the file header's services row); false where the entry or the seal does not open.
func (self *mailM8World) openServices(indexer sidecar.ConfigIndexer) ([]protocol.IndexerService, bool) {
	entry := &bridge.AuthEntry{}
	if proto.Unmarshal(self.admission.Entry(indexer.At), entry) != nil || entry.GetKind() != bridge.AuthEntryKindStatement {
		return nil, false
	}
	signed := &bridge.Signed{}
	if proto.Unmarshal(entry.GetBody(), signed) != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_INDEXER_SET) {
		return nil, false
	}
	designation := &protocol.IndexerSet{}
	if proto.Unmarshal(signed.GetBody(), designation) != nil {
		return nil, false
	}
	services := &protocol.IndexerServices{}
	context := sidecar.NewConfigSealContext(bridge.SignedType_SIGNED_INDEXER_SET, designation.GetHeader())
	if _, err := sidecar.OpenConfigBody(indexer.SealedServices, context, self.configKeyAt, services); err != nil {
		return nil, false
	}
	return services.GetServices(), true
}

// Files device's IndexerSet at member scope for services as its own act does (Sidecar.DesignateIndexer): signed by
// the device, its services sealed to the config's generation under the statement's own header. Then every engine
// takes the tip.
func (self *mailM8World) Designate(device *sidecartest.AdmissionDevice, services ...protocol.IndexerService) {
	self.t.Helper()
	header := self.admission.Header()
	sealed, err := sidecar.SealConfigBody(self.configKey, sidecar.NewConfigSealContext(bridge.SignedType_SIGNED_INDEXER_SET, header), &protocol.IndexerServices{Services: services}, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	self.admission.MustLand(self.admission.Sign(device, bridge.SignedType_SIGNED_INDEXER_SET, &protocol.IndexerSet{
		Header: header, SidecarId: device.SidecarId.Bytes(), Scope: protocol.IndexerScope_INDEXER_SCOPE_MEMBER, SealedServices: sealed,
	}))
	self.Install()
}

// A sign-up message to recipient from the shop, its code in the body, with subject.
func mailM8Message(recipient string, subject string, body string) []byte {
	return []byte(strings.Join([]string{
		"From: Shop <signup@" + mailM8SenderDomain + ">",
		"To: <" + recipient + ">",
		"Subject: " + subject,
		"Date: Thu, 19 Nov 2026 12:00:00 +0000",
		"Message-ID: <" + fmt.Sprintf("%x", sha256.Sum256([]byte(recipient+subject)))[:16] + "@" + mailM8SenderDomain + ">",
		"",
		body,
		"",
	}, "\r\n"))
}

// One message to recipient through the router and the receiver's session: the reply to its end of DATA, or the first
// reply before it that was not 250.
func (self *mailM8World) Send(recipient string, subject string, body string) *sidecartest.MailReply {
	self.t.Helper()
	return self.mail.Send(mailM8Sender, self.mail.Settings().MxHost(), "signup@"+mailM8SenderDomain, []string{recipient}, mailM8Message(recipient, subject, body))
}

// Every deposit the receiver left, ingested on the owner's laptop, as its component's ingest takes them: each message
// written, by subject.
func (self *mailM8World) Ingest() map[string]*sidecar.MailMessage {
	self.t.Helper()
	messages := map[string]*sidecar.MailMessage{}
	ingestor := self.mail.Ingestor(self.ownerEvs, self.owner.SidecarId, func(message *sidecar.MailMessage) {
		messages[message.Entry.GetSubject()] = message
	}, nil)
	if _, err := ingestor.Ingest(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	return messages
}

// The receiver that took each deposit standing in the mailbox, by subject, as the deposit's trailer names it.
func (self *mailM8World) Depositors() map[string]sidecar.Id {
	self.t.Helper()
	deposits, err := self.mail.StandingDeposits(self.ownerEvs)
	if err != nil {
		self.t.Fatal(err)
	}
	depositors := map[string]sidecar.Id{}
	for _, deposit := range deposits {
		subject := ""
		for _, line := range strings.Split(string(deposit.Message), "\r\n") {
			if value, ok := strings.CutPrefix(line, "Subject: "); ok {
				subject = value
				break
			}
		}
		receiverId, err := sidecar.IdFromBytes(deposit.Trailer.GetReceiverSidecarId())
		if err != nil {
			self.t.Fatalf("a deposit's trailer names no receiver: %v", err)
		}
		depositors[subject] = receiverId
	}
	return depositors
}

// The indexer paths (the file header's indexer paths row): a desktop ur daemon, a NAS and a VPS each take mail as a
// designated indexer, and until one is designated an online receiver still takes it, coverage reads foreground-only
// and Status carries the prompt (FS-82's M8 case).
func TestMailM8IndexerPathsTakeMailAndEndThePrompt(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	for i, host := range []string{"desktop daemon", "nas", "vps"} {
		world := newMailM8World(t, net, &mailM8WorldSettings{ReceiverName: host, Label: fmt.Sprintf("lbl%07d", i+1), Host: mailM8Host(t, net)})
		ctx := world.ctx

		status, err := world.ownerMail.Status(ctx)
		if err != nil || !status.Enabled || !status.MailIndexerKnown || status.MailIndexer || status.Prompt != sidecar.MailIndexerPrompt {
			t.Fatalf("%s: before a designation, status %+v: %v", host, status, err)
		}
		if coverage, err := world.ownerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageForegroundOnly {
			t.Fatalf("%s: before a designation, coverage %s: %v", host, coverage, err)
		}
		created, err := world.ownerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: "https://" + mailM8SenderDomain + "/signup"})
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if created.CoverageCopy != sidecar.MailCoverageForegroundOnlyCopy {
			t.Fatalf("%s: the first burner's copy %q", host, created.CoverageCopy)
		}
		world.SyncReceiver()
		// FS-82's M8 case: with no mail indexer an online receiver still takes mail
		if reply := world.Send(created.Address, "before a designation", "Your verification code is 482913."); !reply.Is(250) {
			t.Fatalf("%s: mail before a designation: %s", host, reply)
		}

		world.Designate(world.receiver, protocol.IndexerService_INDEXER_SERVICE_MAIL)
		if indexers := world.admission.State().Indexers(); len(indexers) != 1 || indexers[0].SidecarId != world.receiver.SidecarId {
			t.Fatalf("%s: the designations %+v", host, indexers)
		}
		if coverage, err := world.ownerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageIndexer {
			t.Fatalf("%s: once designated, coverage %s: %v", host, coverage, err)
		}
		status, err = world.ownerMail.Status(ctx)
		if err != nil || !status.MailIndexerKnown || !status.MailIndexer || status.Prompt != "" {
			t.Fatalf("%s: once designated, status %+v: %v", host, status, err)
		}
		if reply := world.Send(created.Address, "to the indexer", "Your verification code is 731004."); !reply.Is(250) {
			t.Fatalf("%s: mail to the designated indexer: %s", host, reply)
		}
		// both under the designated receiver's own identity, and ingested as the burner's mail
		for subject, depositorId := range world.Depositors() {
			if depositorId != world.receiver.SidecarId {
				t.Fatalf("%s: %q was deposited by %s, not the %s", host, subject, depositorId, host)
			}
		}
		messages := world.Ingest()
		for _, subject := range []string{"before a designation", "to the indexer"} {
			message := messages[subject]
			if message == nil || message.DepositorId != world.receiver.SidecarId {
				t.Fatalf("%s: %q was not ingested from the %s: %+v", host, subject, host, message)
			}
		}
	}
}

// CreateBurner's copy before a first burner (the file header's copy row): under none and foreground-only the
// foreground-only copy, the burner made all the same; under indexer none; and a later burner none.
func TestMailM8CreateBurnerShowsTheCopyBeforeAFirstBurner(t *testing.T) {
	cases := []struct {
		name      string
		policy    string
		designate bool
		coverage  sidecar.MailCoverage
		copy      string
	}{
		{name: "no receiver", policy: mailM8PolicyNoReceiver, coverage: sidecar.MailCoverageNone, copy: sidecar.MailCoverageForegroundOnlyCopy},
		{name: "receivers and no indexer", policy: mailM8PolicyReceive, coverage: sidecar.MailCoverageForegroundOnly, copy: sidecar.MailCoverageForegroundOnlyCopy},
		{name: "a mail indexer", policy: mailM8PolicyReceive, designate: true, coverage: sidecar.MailCoverageIndexer},
	}
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	for i, c := range cases {
		world := newMailM8World(t, net, &mailM8WorldSettings{Policy: c.policy, Label: fmt.Sprintf("lbl%07d", i+1), Host: mailM8Host(t, net)})
		ctx := world.ctx
		if c.designate {
			world.Designate(world.receiver, protocol.IndexerService_INDEXER_SERVICE_MAIL)
		}
		if coverage, err := world.ownerMail.ReceiverCoverage(ctx); err != nil || coverage != c.coverage {
			t.Fatalf("%s: coverage %s: %v", c.name, coverage, err)
		}
		first, err := world.ownerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: "first.example"})
		if err != nil {
			t.Fatalf("%s: a first burner refused: %v", c.name, err)
		}
		if first.CoverageCopy != c.copy {
			t.Fatalf("%s: the first burner's copy %q, want %q", c.name, first.CoverageCopy, c.copy)
		}
		second, err := world.ownerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: "second.example"})
		if err != nil || second.CoverageCopy != "" || second.Label == first.Label {
			t.Fatalf("%s: a second burner %+v: %v", c.name, second, err)
		}
		// the copy speaks of receiving alone: a send's limits are CheckSend's (FS-123's clause as reading 21 reads it)
		text := strings.ToLower(first.CoverageCopy)
		for _, word := range []string{"send", "sent", "outbound"} {
			if strings.Contains(text, word) {
				t.Fatalf("%s: the copy speaks of sending: %q", c.name, first.CoverageCopy)
			}
		}
	}
}

// One host of an Fs98World, a real ur daemon: its Sidecar, in a real Daemon, is admitted and consented in the network
// and is the designator of a MailClient bound to the world on an evs client its own keychain signs for.
type mailM8DaemonHost struct {
	host   *sidecartest.Fs98Host
	engine *sidecar.AclEngine
	mail   *sidecar.MailClient
}

// A daemon host named name of the owner's member, confirmed by the owner's laptop, its MailClient on settings, nil
// for a daemon's.
func (self *mailM8World) daemonHost(fs98 *sidecartest.Fs98World, name string, settings *sidecar.MailSettings) *mailM8DaemonHost {
	self.t.Helper()
	host := fs98.AddHost(name, self.owner.MemberId, self.owner, 0)
	fs98.OwnerConfirm(self.owner, host.Device)
	if !self.admission.Consented(host.Device, self.owner.MemberId) {
		self.t.Fatalf("%s is not consented", name)
	}
	running := host.Sidecar.Sidecar()
	identity := running.Identity()
	evs := self.mail.DeviceOf(identity.SidecarId, identity.IdentityPublicKey, running.Sign, false, sidecartest.NewFakeStore().Root(), nil)
	engine := self.Engine(identity.SidecarId)
	return &mailM8DaemonHost{host: host, engine: engine, mail: self.mailClient(identity.SidecarId, evs, engine, running, settings)}
}

// The act row (the file header's act row): SetReceiverEnabled on a real ur daemon files its designation through its
// Sidecar's act, a retry files none, the owner's coverage reads indexer and the prompt goes, and false retires it; an
// MCP origin files nothing, and an Android or iOS app host is never a mail indexer (owner decision 197).
func TestMailM8ReceiverEnabledOnARealDaemonFilesItsDesignation(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	fs98Settings := sidecartest.DefaultFs98Settings()
	fs98Settings.AclCompile = sidecartest.AclAdmissionCompile
	fs98 := sidecartest.NewFs98World(t, net, fs98Settings)
	t.Cleanup(fs98.Close)
	world := newMailM8World(t, net, &mailM8WorldSettings{Admission: fs98.Admission()})
	ctx := world.ctx
	daemon := world.daemonHost(fs98, "desktop daemon host", nil)
	tip := func() uint64 {
		fs98.Settle()
		return world.admission.Tip().GetVersion()
	}

	before := tip()
	if err := daemon.mail.SetReceiverEnabled(ctx, true, sidecar.SidecarActMcp, nil); !errors.Is(err, sidecar.ErrMailHostNotConfirmed) {
		t.Fatalf("a designation through MCP: %v", err)
	}
	if after := tip(); after != before {
		t.Fatalf("an MCP origin moved the log from %d to %d", before, after)
	}
	for _, profile := range []sidecar.MailHostProfile{sidecar.MailHostProfileAndroid, sidecar.MailHostProfileIos} {
		settings := sidecar.DefaultMailSettings()
		sidecar.ApplyMobileMailSettings(settings, profile)
		phone := world.daemonHost(fs98, string(profile)+" app host", settings)
		before := tip()
		if err := phone.mail.SetReceiverEnabled(ctx, true, sidecar.SidecarActConfirmed, nil); !errors.Is(err, sidecar.ErrMailHostNotIndexer) {
			t.Fatalf("the %s app host's designation: %v", profile, err)
		}
		if after := tip(); after != before {
			t.Fatalf("the %s app host moved the log from %d to %d", profile, before, after)
		}
	}

	if err := daemon.mail.SetReceiverEnabled(ctx, true, sidecar.SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	filed := tip()
	world.Install()
	indexers := world.admission.State().Indexers()
	daemonId := daemon.host.Device.SidecarId
	if len(indexers) != 1 || indexers[0].SidecarId != daemonId || indexers[0].Signer != daemonId || indexers[0].Scope != protocol.IndexerScope_INDEXER_SCOPE_MEMBER {
		t.Fatalf("the designations %+v", indexers)
	}
	if services, ok := world.openServices(indexers[0]); !ok || !slices.Equal(services, []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL}) {
		t.Fatalf("the designation's services %v, opened %t", services, ok)
	}
	// a retry finds mail filed already
	if err := daemon.mail.SetReceiverEnabled(ctx, true, sidecar.SidecarActConfirmed, nil); err != nil || tip() != filed {
		t.Fatalf("a retry: %v, the log at %d after %d", err, world.admission.Tip().GetVersion(), filed)
	}
	if coverage, err := world.ownerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageIndexer {
		t.Fatalf("the owner's coverage with the daemon designated: %s: %v", coverage, err)
	}
	if status, err := world.ownerMail.Status(ctx); err != nil || status.Prompt != "" {
		t.Fatalf("the owner's status with the daemon designated: %+v: %v", status, err)
	}

	if err := daemon.mail.SetReceiverEnabled(ctx, false, sidecar.SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	tip()
	world.Install()
	if indexers := world.admission.State().Indexers(); len(indexers) != 0 {
		t.Fatalf("after the retirement, designations %+v", indexers)
	}
	if coverage, err := world.ownerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageForegroundOnly {
		t.Fatalf("the owner's coverage after the retirement: %s: %v", coverage, err)
	}
	if status, err := world.ownerMail.Status(ctx); err != nil || status.Prompt != sidecar.MailIndexerPrompt {
		t.Fatalf("the owner's status after the retirement: %+v: %v", status, err)
	}
}

// plan-KEYS-hint-addressing's resolution, which no route serves yet (server's router block runs with none, so every
// hint by sidecar is lost there): each sidecar's current client, as the host's resolver is to answer it (§6.8).
type mailM8PushResolver struct {
	stateLock sync.Mutex
	clientIds map[connect.Id]connect.Id
}

func (self *mailM8PushResolver) PushClientIds(ctx context.Context, sidecarIds []connect.Id) (map[connect.Id]connect.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	resolved := map[connect.Id]connect.Id{}
	for _, sidecarId := range sidecarIds {
		if clientId, ok := self.clientIds[sidecarId]; ok {
			resolved[sidecarId] = clientId
		}
	}
	return resolved, nil
}

// FS-36's forced router miss with SDK-M8-12's wake path (the file header's FS-36 row): the router's own miss holds the
// session and its forced MailHint{RECEIVER_NEEDED} goes through the waking hint writer, its enqueue and the push
// sender, so the lapsed receiver's token is woken once and at once, though live was just refreshed, its payload a topic
// class and a version alone (WK4); then the receiver registers, the hold's next Find takes the session, and the
// message is deposited by that receiver, with no second wake.
func TestMailM8Fs36ForcedRouterMissWakesTheReceiverOnceAtOnce(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	host := mailM8Host(t, net)
	sidecartest.RegisterPushScripts(host.Redis)
	clock := net.Clock()
	ctx := t.Context()

	// the wake path as server's router block builds it: the waking hint writer over the host's Redis with its enqueue,
	// and the sender reading the queue into two vendor sinks, each wait long so the only timers are the schedule's
	senderSettings := pushservice.DefaultWakeSenderSettings()
	senderSettings.ReadBlock = 100 * time.Hour
	senderSettings.ClaimInterval = 1000 * time.Hour
	senderSettings.GateInterval = 10000 * time.Hour
	shardCount := pushservice.DefaultWakeQueueSettings().ShardCount
	if senderSettings.Queue != nil {
		shardCount = senderSettings.Queue.ShardCount
	}
	for shard := range shardCount {
		if err := host.Redis.StreamGroupCreate(ctx, pushservice.WakeQueueKey(shard), senderSettings.ConsumerGroup); err != nil {
			t.Fatal(err)
		}
	}
	metrics := sidecartest.NewFakeMetrics(nil)
	enqueuer, err := pushservice.NewWakeEnqueuer(host.Redis, senderSettings.Queue, clock, func() bool { return true }, metrics)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &mailM8PushResolver{clientIds: map[connect.Id]connect.Id{}}
	writer, err := pushservice.NewWakingHintWriter(host.Redis, nil, resolver, metrics, enqueuer)
	if err != nil {
		t.Fatal(err)
	}
	lapsed := &atomic.Bool{}
	lapsed.Store(true)
	world := newMailM8World(t, net, &mailM8WorldSettings{Host: host, MailWorld: func(settings *mailworld.MailWorldSettings) {
		settings.Router = func(router *mxedgeservice.MxEdgeSettings) {
			router.WakeHold = true
		}
		settings.Push = writer
		// the receiver's registration lapsed: the Find answers no listener until it registers again
		settings.DialRefusal = func(request *mxedgeservice.MxEdgeDialRequest) error {
			if lapsed.Load() {
				return &sidecar.SocketCodeError{Err: sidecar.ErrSocketNoListener}
			}
			return nil
		}
	}})

	// the receiver's client, its keys in slots apart from its wake shard's (WK1), with a wake token and live just
	// refreshed, so an unforced hint would be put off
	var clientId connect.Id
	for range 64 {
		clientId = connect.NewId()
		shardKey := pushservice.WakeQueueKey(pushservice.WakeQueueShard(clientId, shardCount))
		if sidecartest.RedisClusterSlot(pushservice.HintTokenKey(clientId)) != sidecartest.RedisClusterSlot(shardKey) {
			break
		}
	}
	resolver.stateLock.Lock()
	resolver.clientIds[connect.Id(world.receiver.SidecarId)] = clientId
	resolver.stateLock.Unlock()
	token := "synthetic-fcm-token-" + clientId.String()[:8]
	t0, err := pushservice.ReadWakeTokenTime(ctx, host.Redis, clientId)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := pushservice.ApplyWakeToken(ctx, host.Redis, &pushservice.WakeTokenRow{ClientId: clientId, Revision: 1, Platform: pushservice.WakePlatformFcm, Token: token}, t0, time.Minute); err != nil || applied != pushservice.WakeTokenApplied {
		t.Fatalf("the token's apply answered %q: %v", applied, err)
	}
	if err := host.Redis.Set(ctx, pushservice.HintLiveKey(clientId), []byte("1"), pushservice.DefaultSidecarPublisherSettings().LiveTimeout); err != nil {
		t.Fatal(err)
	}
	vendors := []*sidecartest.FakeWakeVendor{
		sidecartest.NewFakeWakeVendor(pushservice.WakePlatformApns, clock), sidecartest.NewFakeWakeVendor(pushservice.WakePlatformFcm, clock),
	}
	settled := make(chan *pushservice.WakeSettled, 64)
	readsEnd := clock.Now().Add(senderSettings.ReadBlock)
	sender, err := pushservice.NewWakeSender(ctx, &pushservice.WakeSenderArgs{
		Redis:    host.Redis,
		Vendors:  []pushservice.WakeVendor{vendors[0], vendors[1]},
		Consumer: "mail-m8",
		Enabled:  func() bool { return true },
		Clock:    clock,
		Metrics:  metrics,
		Settings: senderSettings,
		Settled: func(result *pushservice.WakeSettled) {
			settled <- result
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.Close)
	// each shard's reader in its read before a hint, as a sender long up is
	world.mail.AwaitTimerCountAt(readsEnd, shardCount)
	submissions := func() []*sidecartest.FakeWakeSubmission {
		found := []*sidecartest.FakeWakeSubmission{}
		for _, vendor := range vendors {
			for _, submission := range vendor.Submissions() {
				if submission.Token == token {
					found = append(found, submission)
				}
			}
		}
		return found
	}

	created, err := world.ownerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: mailM8SenderDomain})
	if err != nil {
		t.Fatal(err)
	}
	world.SyncReceiver()
	mta := world.mail.Connect(mailM8Sender)
	defer mta.Close()
	world.mail.Greet(mta, "relay."+mailM8SenderDomain)
	handshake := make(chan error, 1)
	go func() {
		_, err := mta.StartTls(sidecartest.MailMtaTlsConfig(world.mail.Settings().MxHost(), tls.VersionTLS13))
		handshake <- err
	}()
	routerSettings := mxedgeservice.DefaultMxEdgeSettings()
	quietAt := clock.Now().Add(routerSettings.StartTlsQuietTimeout)
	world.mail.AwaitTimerAt(quietAt)
	clock.Advance(quietAt.Sub(clock.Now()))
	missAt := clock.Now()

	// the miss: held, and its forced hint woken at once
	select {
	case result := <-settled:
		if result.ClientId != clientId || result.Result != pushservice.WakeSettledSent || result.TopicClass != "mail" || result.Platform != pushservice.WakePlatformFcm {
			t.Fatalf("the wake %+v", result)
		}
	case <-time.After(world.mail.Settings().StepTimeout):
		t.Fatal("the router's miss woke no one")
	}
	woken := submissions()
	if len(woken) != 1 || !woken[0].At.Equal(missAt) || woken[0].Payload.TopicClass != "mail" || woken[0].Payload.Version != uint64(missAt.UnixMilli()) {
		t.Fatalf("the submissions %+v at the miss %v", woken, missAt)
	}
	for _, body := range [][]byte{woken[0].Body, []byte(fmt.Sprint(woken[0].Payload))} {
		for _, id := range []string{clientId.String(), world.receiver.SidecarId.String(), world.admission.NetworkId().String()} {
			if bytes.Contains(body, []byte(id)) {
				t.Fatalf("the wake carries an id: %q", body)
			}
		}
	}
	select {
	case err := <-handshake:
		t.Fatalf("the held session's handshake ended before a receiver registered: %v", err)
	default:
	}

	// the receiver registers again, and the hold's next Find takes the session
	lapsed.Store(false)
	retryAt := missAt.Add(routerSettings.WakeHoldFindInterval)
	world.mail.AwaitTimerAt(retryAt)
	clock.Advance(retryAt.Sub(clock.Now()))
	select {
	case err := <-handshake:
		if err != nil {
			t.Fatalf("the held session's handshake: %v", err)
		}
	case <-time.After(world.mail.Settings().StepTimeout):
		t.Fatal("the held session never spliced")
	}
	if reply, err := mta.Ehlo("relay." + mailM8SenderDomain); err != nil || !reply.Is(250) {
		t.Fatalf("EHLO inside TLS: %s %v", reply, err)
	}
	if reply, err := mta.MailFrom("signup@" + mailM8SenderDomain); err != nil || !reply.Is(250) {
		t.Fatalf("MAIL: %s %v", reply, err)
	}
	if reply, err := mta.RcptTo(created.Address); err != nil || !reply.Is(250) {
		t.Fatalf("RCPT: %s %v", reply, err)
	}
	if reply, err := mta.Data(mailM8Message(created.Address, "held for the receiver", "Your verification code is 220917.")); err != nil || !reply.Is(250) {
		t.Fatalf("DATA: %s %v", reply, err)
	}
	world.mail.Finish(mta)
	if message := world.Ingest()["held for the receiver"]; message == nil || message.DepositorId != world.receiver.SidecarId {
		t.Fatalf("the held message was not ingested from the receiver: %+v", message)
	}
	if woken := submissions(); len(woken) != 1 {
		t.Fatalf("%d submissions for one hold", len(woken))
	}
}
