//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// The world M8's composed mail runs stand on (MAIL-M8-10; mail_m8_test.go's rows and S10's receive-only half, s10.go):
// one network with mail on, exported so the test that runs a row on T2 and server's test that runs it on T3 build the
// same world, never two hand copies.
//
// The network's §8 state is the admission suite's real log with ACL's own compile (AdmissionNet), on the Net's tier: T2's
// FakeApi, or server's sequencer on T3. Every device's AclEngine holds its state and its head's local policy as
// AclFollower installs them. evs and gkm are MailWorld's, whose router, receiver session and engine S7 composes, lined
// up on the log's ids and keys, its mailcfg the network's; the receiver resolves recipients over its own MailConfig of
// that mailcfg, as mail_component_receive.go's resolver does; the owner's laptop runs a MailClient bound to the world
// as the component binds one, with its own stand-ins where no host has a part yet:
//
//	gate       §5.4's gate as another approval-capable device's decision leaves it: each outward action's effect run
//	           once under a use key drawn from its bytes (M8Gate). §16.6's real gate is the approval suite's
//	api        POST /mail/enable, GET /mail/status and GET /sidecar/limits as api answers them, each call counted
//	           (M8Api), on T3 as well: no test Sidecar's mail component runs against server's routes yet
//	services   a designation's sealed services opened with the config's generation key under its statement's header,
//	           read from the log's entry at the designation's position: the component binds no opener until
//	           ConfigIndexer carries the header's nonce (QD-1096), so no running Sidecar reads indexer yet
//	indexer    Status's MailIndexer, the component's mailIndexerCovers, answered from ReceiverCoverage
//
// Every name and address is synthetic: .example names and RFC 5737 and 3849 addresses (connect/CODESTYLE.md's test
// data rule).

package mailworld

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The root the network's addresses are under by default, which the DNS harness serves by default, and a network's
// label by default.
const (
	M8Root  = "harness.example"
	M8Label = "lbl0000001"
)

// The sender of sign-up mail, RFC 5737's, and its domain.
var M8Sender = netip.MustParseAddr("198.51.100.44")

const M8SenderDomain = "shop.example"

// Members hold burners and receive: listen on every mail alias, so a member's records route (D-ACL-12), and on the
// receiver's socket, so a member's device may receive.
const M8PolicyReceive = `{"grants": [
	{"src": ["autogroup:member"], "dst": ["mail:*"], "allow": ["listen"]},
	{"src": ["autogroup:member"], "dst": ["sock:smtp/25/mx"], "allow": ["listen"]}
]}`

// Members hold burners, and no device may receive: coverage none.
const M8PolicyNoReceiver = `{"grants": [{"src": ["autogroup:member"], "dst": ["mail:*"], "allow": ["listen"]}]}`

// What a M8World is built with.
type M8WorldSettings struct {
	// The receiver's device by its host's name: "desktop daemon", "nas" or "vps".
	ReceiverName string
	// The network's policy document.
	Policy string
	// The user root the network's label is under: M8Root when empty.
	Root string
	// The network's label: M8Label when empty.
	Label string
	// The host the world's router, receiver and evs run on: the Net's fakes when nil, which a scenario's harness
	// captures; a test running several worlds on one Net gives each its own (NewFakeHost on the Net's clock).
	Host *sidecartest.FakeHost
	// Changes the MailWorld's settings once the world has set its own, such as the router's wake hold; nil none.
	MailWorld func(settings *MailWorldSettings)
	// A network another world of the test already runs, an Fs98World's, whose owner's laptop the world takes; nil
	// bootstraps one on the Net's tier.
	Admission *sidecartest.AdmissionNet
	// The stores each of the MailWorld's services runs on (MailWorldSettings.Stores): nil for the host's own.
	Stores func(service string) *sidecar.ServiceHost
}

// GET /sidecar/limits, GET /mail/status and POST /mail/enable as api answers them, counted. Safe for concurrent use.
type M8Api struct {
	clock sidecar.Clock

	stateLock sync.Mutex
	limits    map[string]int64
	calls     map[string]int
}

func newM8Api(clock sidecar.Clock) *M8Api {
	return &M8Api{
		clock: clock,
		limits: map[string]int64{
			"mail_inbound_message_bytes": 50 * 1024 * 1024, "mail_inbound_recipients": 100, "mail_inbound_repos_per_message": 8,
			"mail_burners_active": 50, "mail_burner_creates_per_day": 20,
		},
		calls: map[string]int{},
	}
}

func (self *M8Api) count(route string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls[route] += 1
}

func (self *M8Api) MailEnable(ctx context.Context) (*sidecar.MailEnabled, error) {
	self.count("POST /mail/enable")
	return &sidecar.MailEnabled{EnabledTime: self.clock.Now()}, nil
}

func (self *M8Api) MailStatus(ctx context.Context) (*sidecar.MailNetworkStatus, error) {
	self.count("GET /mail/status")
	return &sidecar.MailNetworkStatus{Enabled: true}, nil
}

func (self *M8Api) Limits(ctx context.Context) (*sidecar.QuotaLimits, error) {
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
func (self *M8Api) Calls() map[string]int {
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
// kind's Lookup kept as Sidecar.RegisterEffectLookup keeps it, a registration replacing the kind's last and a removal
// taking only the one it added, so a component's stale removal leaves a newer one standing. Safe for concurrent use.
type M8Gate struct {
	stateLock sync.Mutex
	lookups   map[sidecar.SidecarActionKind]*m8GateLookup
	outcomes  map[string]*sidecar.SidecarOutcome
	actions   []*sidecar.SidecarAction
}

// One registered Lookup, compared by its entry so a stale removal leaves a newer one.
type m8GateLookup struct {
	lookup sidecar.SidecarEffectLookup
}

func newM8Gate() *M8Gate {
	return &M8Gate{lookups: map[sidecar.SidecarActionKind]*m8GateLookup{}, outcomes: map[string]*sidecar.SidecarOutcome{}}
}

// The key of the use an action's bytes are spent under.
func m8EffectKey(canonical []byte) []byte {
	key := sha256.Sum256(append([]byte("mail m8 use of "), canonical...))
	return key[:]
}

func (self *M8Gate) Authorize(ctx context.Context, action *sidecar.SidecarAction, decision *bridge.Signed) error {
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
	effectRef, runErr := action.Effect.Run(ctx, m8EffectKey(action.Canonical))
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

func (self *M8Gate) RegisterEffectLookup(kind sidecar.SidecarActionKind, lookup sidecar.SidecarEffectLookup) func() {
	entry := &m8GateLookup{lookup: lookup}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lookups[kind] = entry
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.lookups[kind] == entry {
			delete(self.lookups, kind)
		}
	}
}

// Whether a Lookup of kind is registered, so the gate would reserve its uses.
func (self *M8Gate) HoldsLookup(kind sidecar.SidecarActionKind) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lookups[kind] != nil
}

// How many actions the gate was handed.
func (self *M8Gate) ActionCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.actions)
}

// The config repo's first generation key, which an IndexerSet's services are sealed to: a group on a fake gkm of its
// own, created by the owner's laptop, as a host's recovery reads the config's keys (fs98.go's config keys).
func m8ConfigKey(t testing.TB, admission *sidecartest.AdmissionNet) *sidecar.EvsRepoKey {
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
func NewM8FakeHost(t testing.TB, net *sidecartest.Net) *sidecartest.FakeHost {
	t.Helper()
	host := sidecartest.NewFakeHost(t.Context(), net.Clock(), nil, nil, nil)
	t.Cleanup(host.Redis.Close)
	return host
}

// One network with mail on (the file header's world). Its exported fields are set once, by NewM8World.
type M8World struct {
	t   testing.TB
	ctx context.Context

	Net       *sidecartest.Net
	Admission *sidecartest.AdmissionNet
	// The owner's laptop, the genesis device, consented and the network's config writer: the user's device.
	Owner *sidecartest.AdmissionDevice
	// The device that runs the receiver, consented too, so its own act may designate it at member scope.
	Receiver *sidecartest.AdmissionDevice

	Root         string
	Label        string
	MailboxId    sidecar.Id
	MailConfigId sidecar.Id
	ConfigKey    *sidecar.EvsRepoKey

	Mail *MailWorld
	Api  *M8Api
	Gate *M8Gate

	OwnerEvs       *sidecar.EvsClient
	OwnerEngine    *sidecar.AclEngine
	OwnerMail      *sidecar.MailClient
	ReceiverEngine *sidecar.AclEngine
	ReceiverConfig *sidecar.MailConfig

	stateLock sync.Mutex
	// every other device's engine, which Install keeps at the tip too
	engines []*sidecar.AclEngine
}

// The world on net (the file header's world), settings nil taking a desktop daemon's receiver under
// M8PolicyReceive.
func NewM8World(t testing.TB, net *sidecartest.Net, settings *M8WorldSettings) *M8World {
	t.Helper()
	if settings == nil {
		settings = &M8WorldSettings{}
	}
	if settings.ReceiverName == "" {
		settings.ReceiverName = "desktop daemon"
	}
	if settings.Policy == "" {
		settings.Policy = M8PolicyReceive
	}
	if settings.Root == "" {
		settings.Root = M8Root
	}
	if settings.Label == "" {
		settings.Label = M8Label
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
	self := &M8World{
		t:            t,
		ctx:          admission.Context(),
		Net:          net,
		Admission:    admission,
		Owner:        owner,
		Receiver:     receiver,
		Root:         settings.Root,
		Label:        settings.Label,
		MailboxId:    admission.Id("mailbox"),
		MailConfigId: admission.Id("mailcfg"),
		Api:          newM8Api(admission.Clock()),
		Gate:         newM8Gate(),
	}
	// the member's mailbox, created by its consented laptop, and the network's mailcfg, by its config writer (§8.8)
	for _, created := range []struct {
		repoId sidecar.Id
		kind   protocol.RepoKind
	}{{repoId: self.MailboxId, kind: protocol.RepoKind_REPO_KIND_MAILBOX}, {repoId: self.MailConfigId, kind: protocol.RepoKind_REPO_KIND_MAILCFG}} {
		admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
			Header: admission.Header(), RepoId: created.repoId.Bytes(), Kind: created.kind,
		}))
	}
	admission.SaveAclPolicy([]byte(settings.Policy), sidecartest.AclSaveMembers{})
	self.ConfigKey = m8ConfigKey(t, admission)

	mailSettings := DefaultMailWorldSettings()
	mailSettings.Root = settings.Root
	mailSettings.Label = settings.Label
	mailSettings.Addresses = nil
	mailSettings.NetworkId = admission.NetworkId()
	mailSettings.MemberId = owner.MemberId
	mailSettings.RepoId = self.MailboxId
	mailSettings.MailConfigRepoId = self.MailConfigId
	mailSettings.Owner = &sidecartest.FakeGkmSigner{SidecarId: owner.SidecarId, PrivateKey: owner.Key}
	mailSettings.Receiver = &sidecartest.FakeGkmSigner{SidecarId: receiver.SidecarId, PrivateKey: receiver.Key}
	mailSettings.Resolve = self.resolve
	mailSettings.Stores = settings.Stores
	if settings.MailWorld != nil {
		settings.MailWorld(mailSettings)
	}
	host := settings.Host
	if host == nil {
		host = net.Fakes()
	}
	self.Mail = NewMailWorld(t, host, net.Clock(), mailSettings)

	self.OwnerEngine = sidecar.NewAclEngine(owner.SidecarId, nil, nil, nil)
	self.ReceiverEngine = sidecar.NewAclEngine(receiver.SidecarId, nil, nil, nil)
	self.Install()

	receiverEvs := self.Mail.Device(self.Mail.Receiver, false, sidecartest.NewFakeStore().Root(), nil)
	receiverConfig, err := sidecar.NewMailConfig(&sidecar.MailConfigArgs{
		Repo:      receiverEvs.Repo(self.MailConfigId),
		Network:   self.Row,
		SidecarId: receiver.SidecarId,
		Authority: &sidecar.MailConfigAclAuthority{Engine: self.ReceiverEngine},
		Clock:     net.Clock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiverConfig.Close)
	self.ReceiverConfig = receiverConfig

	self.OwnerEvs = self.Mail.Device(self.Mail.Owner, false, sidecartest.NewFakeStore().Root(), nil)
	self.OwnerMail = self.MailClient(owner.SidecarId, self.OwnerEvs, self.OwnerEngine, nil, nil)
	return self
}

// What the network's followers and the world's clients run under, which ends with the network.
func (self *M8World) Context() context.Context {
	return self.ctx
}

// The network's zone under its root, <label>.<root>.
func (self *M8World) Zone() string {
	return self.Label + "." + self.Root
}

// A MailClient of sidecarId bound to the world as the component binds one (the file header's world): evs over evs,
// §8 through engine, the network's state, the gate, the api and the stand-ins for its services opener and its
// indexer answer; designator files its designations, configKey nil taking the world's. settings nil is the daemon's.
func (self *M8World) MailClient(sidecarId sidecar.Id, evs *sidecar.EvsClient, engine *sidecar.AclEngine, designator sidecar.MailIndexerDesignator, settings *sidecar.MailSettings) *sidecar.MailClient {
	self.t.Helper()
	client, err := sidecar.NewMailClient(&sidecar.MailClientArgs{
		NetworkId: self.Admission.NetworkId(),
		SidecarId: sidecarId,
		Store:     sidecartest.NewFakeStore().Root(),
		Settings:  settings,
		Clock:     self.Net.Clock(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	client.Bind(&sidecar.MailBinding{
		Evs:             evs,
		Engine:          engine,
		Network:         self.Row,
		Gate:            self.Gate,
		Api:             self.Api,
		Config:          self.Config,
		IndexerServices: self.OpenServices,
		MailIndexer: func() (bool, error) {
			coverage, err := client.ReceiverCoverage(self.ctx)
			return coverage == sidecar.MailCoverageIndexer, err
		},
		Designator: designator,
		ConfigKey: func(ctx context.Context) (*sidecar.EvsRepoKey, error) {
			return self.ConfigKey, nil
		},
	})
	return client
}

// The network's row under its root.
func (self *M8World) Row() sidecar.NetworkLabelRow {
	return sidecar.NetworkLabelRow{Root: self.Root, NetworkId: self.Admission.NetworkId(), Label: self.Label}
}

// The network's verified state at the tip, every device's.
func (self *M8World) Config() (*sidecar.ConfigState, error) {
	return self.Admission.State(), nil
}

// Installs the tip's acl state and its config head's local policy in every device's engine, as each device's
// AclFollower does once its ConfigClient applied the tip (acl_follow.go's apply and compileLocal).
func (self *M8World) Install() {
	self.t.Helper()
	state := self.Admission.State()
	acl, err := state.Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	base := state.Base()
	head, err := self.Admission.Heads().ReadConfigHead(self.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
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
		return append([]*sidecar.AclEngine{self.OwnerEngine, self.ReceiverEngine}, self.engines...)
	}()
	for _, engine := range engines {
		if err := engine.Install(acl, local); err != nil {
			self.t.Fatal(err)
		}
	}
}

// An engine of another device, which Install keeps at the tip with the rest.
func (self *M8World) Engine(sidecarId sidecar.Id) *sidecar.AclEngine {
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
func (self *M8World) resolve(ctx context.Context, address string) (*sidecar.MailSessionRecipient, error) {
	recipient, err := sidecar.ParseMailRecipient(self.Root, address)
	if err != nil {
		return &sidecar.MailSessionRecipient{}, nil
	}
	lookup, err := self.ReceiverConfig.Resolve(ctx, recipient)
	if err != nil {
		return nil, err
	}
	return &sidecar.MailSessionRecipient{Known: lookup.Known, Address: recipient.Address(), RepoId: lookup.MailboxRepoId}, nil
}

// The receiver's mailcfg read again, as an evs hint of mailcfg's change has the receiver's follower do.
func (self *M8World) SyncReceiver() {
	self.t.Helper()
	if err := self.ReceiverConfig.Sync(self.ctx); err != nil {
		self.t.Fatal(err)
	}
}

// The config generation's key, for the generation it is.
func (self *M8World) configKeyAt(generation uint64) *sidecar.EvsRepoKey {
	if self.ConfigKey == nil || self.ConfigKey.Generation() != generation {
		return nil
	}
	return self.ConfigKey
}

// A designation's sealed services, opened with the config's generation key under the header of the statement at its
// position in the log (the file header's services row); false where the entry or the seal does not open.
func (self *M8World) OpenServices(indexer sidecar.ConfigIndexer) ([]protocol.IndexerService, bool) {
	entry := &bridge.AuthEntry{}
	if proto.Unmarshal(self.Admission.Entry(indexer.At), entry) != nil || entry.GetKind() != bridge.AuthEntryKindStatement {
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
func (self *M8World) Designate(device *sidecartest.AdmissionDevice, services ...protocol.IndexerService) {
	self.t.Helper()
	header := self.Admission.Header()
	sealed, err := sidecar.SealConfigBody(self.ConfigKey, sidecar.NewConfigSealContext(bridge.SignedType_SIGNED_INDEXER_SET, header), &protocol.IndexerServices{Services: services}, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	self.Admission.MustLand(self.Admission.Sign(device, bridge.SignedType_SIGNED_INDEXER_SET, &protocol.IndexerSet{
		Header: header, SidecarId: device.SidecarId.Bytes(), Scope: protocol.IndexerScope_INDEXER_SCOPE_MEMBER, SealedServices: sealed,
	}))
	self.Install()
}

// A sign-up message to recipient from the shop, its code in the body, with subject.
func M8Message(recipient string, subject string, body string) []byte {
	return []byte(strings.Join([]string{
		"From: Shop <signup@" + M8SenderDomain + ">",
		"To: <" + recipient + ">",
		"Subject: " + subject,
		"Date: Thu, 19 Nov 2026 12:00:00 +0000",
		"Message-ID: <" + fmt.Sprintf("%x", sha256.Sum256([]byte(recipient+subject)))[:16] + "@" + M8SenderDomain + ">",
		"",
		body,
		"",
	}, "\r\n"))
}

// One message to recipient through the router and the receiver's session: the reply to its end of DATA, or the first
// reply before it that was not 250.
func (self *M8World) Send(recipient string, subject string, body string) *sidecartest.MailReply {
	self.t.Helper()
	return self.Mail.Send(M8Sender, self.Mail.Settings().MxHost(), "signup@"+M8SenderDomain, []string{recipient}, M8Message(recipient, subject, body))
}

// Every deposit the receiver left, ingested on the owner's laptop, as its component's ingest takes them: each message
// written, by subject.
func (self *M8World) Ingest() map[string]*sidecar.MailMessage {
	self.t.Helper()
	messages := map[string]*sidecar.MailMessage{}
	ingestor := self.Mail.Ingestor(self.OwnerEvs, self.Owner.SidecarId, func(message *sidecar.MailMessage) {
		messages[message.Entry.GetSubject()] = message
	}, nil)
	if _, err := ingestor.Ingest(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	return messages
}

// The receiver that took each deposit standing in the mailbox, by subject, as the deposit's trailer names it.
func (self *M8World) Depositors() map[string]sidecar.Id {
	self.t.Helper()
	deposits, err := self.Mail.StandingDeposits(self.OwnerEvs)
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
