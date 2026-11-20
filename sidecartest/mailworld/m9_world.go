//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// The world M9's composed mail runs stand on (MAIL-M9-06; mail_m9_test.go's rows and S10's replying half,
// s10_replying.go): an M8World whose owner's laptop also sends, as a desktop ur daemon does, so a row runs MAIL's sending
// code end to end with SMTP's outbound path behind it, and adds no mechanism. What the world adds to M8's:
//
//	client     the owner's laptop's MailClient bound as M8World binds one, with what sending binds besides: the device's
//	           identity key signing its o/ entries (Sidecar.Sign), the network's standing as GET /abuse/status answers
//	           a verified standard network, and the laptop's SmtpDkimKeys as the burner selectors a burn retires
//	           (MAIL-M9-03). Policy lets every member send as and listen on every alias (M9PolicySend)
//	prover     the same laptop as the member's prover host (D-SMTP-18; §15.10's step 4): its SmtpProverHost writes its
//	           p/, its SmtpOutboxRunner takes the member's o/ entries and its SmtpSender sends them, each over the member's
//	           own mailbox as MAIL serves it (MailClient.SmtpMailbox, mailSmtpMailbox over o/, or/, p/ and DSN deposits),
//	           through SMTP's stub edge and its FakeSmtpProver to ScriptedMxs in an MxWorld behind a synthetic web PKI
//	           (SmtpSendWorld, SMTP-M9-31's), on the Net's clock
//	dkim       POST /smtp/dkim-keys: what a row gives, S10's server half that writes the zone, or by default an answer to
//	           every publish and retire, each call kept for the row to read
//	component  when a row asks (M9WorldSettings.Component), the client's own component (MailClient.Attach): its ingest
//	           pass is the member's reader, which files what the receiver or the sender's DSNs deposited and runs
//	           forwarding and relay (mail_forward.go), so S6's forwarding rows and FS-123's DSNs run through it, a wake
//	           (MailClient.Resync) starting a pass and the pass's CONSUME barrier showing its messages handed on (Ingest)
//
// One stand-in is this file's, the component's alone: the MailWorld's evs pins every push and deposit at its own fake
// auth log's positions (world.go), which the admission log never held, so the laptop's engine, which judges a deposit's
// depositor at its pin (MailIngestAclAuthority), reads that pin at the admission log's newest state
// (m9WorldEngineStates). Nothing in a row changes the network's state between a deposit and its ingest.
//
// Every name and address is synthetic: .example names and RFC 5737 addresses (connect/CODESTYLE.md's test data rule).
// Nothing sleeps: a step waits on a barrier, a pipe or the clock a test moves.

package mailworld

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Members send as and listen on every alias, and receive: the M8 receive policy with send (D-ACL-12).
const M9PolicySend = `{"grants": [
	{"src": ["autogroup:member"], "dst": ["mail:*"], "allow": ["listen", "send"]},
	{"src": ["autogroup:member"], "dst": ["sock:smtp/25/mx"], "allow": ["listen"]}
]}`

// What a M9World is built with: DefaultM9WorldSettings, changed.
type M9WorldSettings struct {
	// The network's M8World: nil takes M8's defaults with M9PolicySend.
	M8 *M8WorldSettings
	// POST /smtp/dkim-keys's server half; nil answers every publish and retire (M9WorldDkim).
	Dkim sidecar.SmtpDkimPublisher
	// The prover host's measured smtp_data_proof_bytes. Positive.
	DataProofByteCount uint64
	// Changes to the sending client's settings once the world has set its own; nil changes none.
	Mail func(settings *sidecar.MailSettings)
	// Changes to the sender's settings; nil changes none.
	Sender func(settings *sidecar.SmtpSenderSettings)
	// Runs the client's component (the file header's component row).
	Component bool
}

func DefaultM9WorldSettings() *M9WorldSettings {
	return &M9WorldSettings{
		// a mebibyte, past every message a row sends but one meant to pass a cap
		DataProofByteCount: 1024 * 1024,
	}
}

// One network whose owner's laptop sends (the file header's world). Its exported fields are set once, by NewM9World.
type M9World struct {
	t   testing.TB
	ctx context.Context

	// The network: its admission log, its MailWorld and the owner's devices.
	M8 *M8World
	// The outbound world: the edge stub, the MxWorld and its ScriptedMxs, the synthetic PKI.
	Send *sidecartest.SmtpSendWorld
	// The owner's laptop's sending client (the file header's client row), and the engine it is bound on.
	Owner       *sidecar.MailClient
	OwnerEngine *sidecar.AclEngine
	// The laptop as prover host (the file header's prover row).
	Dkim       *sidecar.SmtpDkimKeys
	Prover     *sidecartest.FakeSmtpProver
	ProverHost *sidecar.SmtpProverHost
	Sender     *sidecar.SmtpSender
	Runner     *sidecar.SmtpOutboxRunner
	// The default publisher, nil when the settings gave one.
	Publisher *M9WorldDkim

	stateLock sync.Mutex
	// every mail_send event the sender raised
	events []sidecar.SidecarEvent
}

// The world on net (the file header's world), settings nil taking DefaultM9WorldSettings.
func NewM9World(t testing.TB, net *sidecartest.Net, settings *M9WorldSettings) *M9World {
	t.Helper()
	if settings == nil {
		settings = DefaultM9WorldSettings()
	}
	m8Settings := &M8WorldSettings{}
	if settings.M8 != nil {
		copied := *settings.M8
		m8Settings = &copied
	}
	if m8Settings.Policy == "" {
		m8Settings.Policy = M9PolicySend
	}
	m8 := NewM8World(t, net, m8Settings)
	self := &M9World{t: t, ctx: m8.Context(), M8: m8}
	clock := net.Clock()

	self.Send = sidecartest.NewSmtpSendWorld(t, &sidecartest.SmtpSendWorldSettings{
		Clock:         clock,
		NetworkDomain: m8.Zone(),
		Sender:        settings.Sender,
	})

	publisher := settings.Dkim
	if publisher == nil {
		self.Publisher = &M9WorldDkim{}
		publisher = self.Publisher
	}
	self.Dkim = sidecar.NewSmtpDkimKeys(newM9WorldSecrets(), publisher, self.Send.Settings, clock, nil)

	// the laptop's engine, at the tip as M8World installs its own, reading any other pin at the tip too
	owner := m8.Owner
	self.OwnerEngine = sidecar.NewAclEngine(owner.SidecarId, &m9WorldEngineStates{admission: m8.Admission}, nil, nil)
	self.install(self.OwnerEngine)

	mailSettings := sidecar.DefaultMailSettings()
	// this laptop is not the network's receiver, which is M8's other device
	mailSettings.Receive.Enabled = false
	// a wake starts the next pass at once, since the clock moves only when a row moves it
	mailSettings.Ingest.MinPassInterval = 0
	if settings.Mail != nil {
		settings.Mail(mailSettings)
	}
	self.Owner = m8.sendingClient(owner, self.OwnerEngine, mailSettings, &m8SendingParts{
		sign:      self.sign,
		standing:  m9WorldStanding,
		selectors: self.Dkim,
	})
	self.buildProver(settings)
	if settings.Component {
		self.attach()
	}
	return self
}

// The laptop's Sidecar.Sign: §6.9's Signed by the owner's identity key.
func (self *M9World) sign(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
	owner := self.M8.Owner
	return &bridge.Signed{
		Body:      body,
		SignerId:  owner.SidecarId.Bytes(),
		Signature: ed25519.Sign(owner.Key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// GET /abuse/status for a verified network in standard standing, which queues internet mail (D-SMTP-14).
func m9WorldStanding(ctx context.Context) (*sidecar.AbuseStatus, error) {
	return &sidecar.AbuseStatus{Standing: sidecar.AbuseStandingStandard, Verified: true}, nil
}

// Installs the tip's acl state and its config head's local policy in engine, as M8World.Install does for its own.
func (self *M9World) install(engine *sidecar.AclEngine) {
	self.t.Helper()
	admission := self.M8.Admission
	state := admission.State()
	acl, err := state.Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	base := state.Base()
	head, err := admission.Heads().ReadConfigHead(self.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
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
	if err := engine.Install(acl, local); err != nil {
		self.t.Fatal(err)
	}
}

// The file header's pins row: any pin reads at the admission log's newest state.
type m9WorldEngineStates struct {
	admission *sidecartest.AdmissionNet
}

func (self *m9WorldEngineStates) AclStateAt(pin *bridge.AuthPin) (*sidecar.AclState, error) {
	return self.admission.State().Acl()
}

// The laptop as prover host (the file header's prover row), built as SmtpSendWorld.AddHost builds a host, over the
// member's own mailbox.
func (self *M9World) buildProver(settings *M9WorldSettings) {
	self.t.Helper()
	send := self.Send
	clock := send.Clock
	owner := self.M8.Owner
	mailbox, err := self.Owner.SmtpMailbox()
	if err != nil {
		self.t.Fatal(err)
	}
	store := sidecartest.NewFakeStore()
	pins := sidecar.NewSmtpPinStore(store.Root(), send.Settings, clock, nil)
	policy := sidecar.NewSmtpTlsPolicy(
		sidecar.NewSmtpDane(send.Anchors, clock, nil),
		sidecar.NewSmtpMtaSts(send.Zone, send.World.MtaStsTransport(), store.Root(), send.Settings, clock),
		pins, sidecar.NewSmtpTlsAllowanceStore(store.Root(), send.Settings, clock), nil, send.Zone, send.Roots,
		send.Settings, clock)
	capByteCount := settings.DataProofByteCount
	proverSettings := sidecartest.SmtpSendWorldProver(capByteCount)
	proverSettings.Measure = &sidecar.SmtpProverMeasure{
		DataProofBytes: capByteCount, DataBytesPerSecond: 512, MeasureTime: clock.Now(), UnitTime: 5 * time.Second,
		HeadByteCount: 831, HeaderRecordByteCount: 1199, EnvelopeGroupCount: 13,
	}
	self.Prover = sidecartest.NewFakeSmtpProver(proverSettings)
	self.ProverHost, err = sidecar.NewSmtpProverHost(&sidecar.SmtpProverHostArgs{
		Prover: self.Prover, Mailbox: mailbox, SidecarId: owner.SidecarId, MailEnabled: func() bool { return true },
		Settings: send.Settings, Clock: clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	// its p/, which the runner's pick and a check read
	if err := self.ProverHost.Idle(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	memberDeviceKey := func(sidecarId sidecar.Id) ed25519.PublicKey {
		if sidecarId == owner.SidecarId {
			return owner.Key.Public().(ed25519.PublicKey)
		}
		return nil
	}
	self.Sender, err = sidecar.NewSmtpSender(&sidecar.SmtpSenderArgs{
		Dialer:       send.StubDialer,
		Prover:       self.Prover,
		Policy:       policy,
		Pins:         pins,
		Dkim:         self.Dkim,
		Mailbox:      mailbox,
		MemberDevice: func(sidecarId sidecar.Id) bool { return memberDeviceKey(sidecarId) != nil },
		Measure:      self.ProverHost.Measure,
		ReadyKeySets: self.ProverHost.ReadyKeySets,
		SendHold:     self.ProverHost.HoldForSend,
		Events: func(event sidecar.SidecarEvent) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.events = append(self.events, event)
		},
		Settings: send.Settings,
		Clock:    clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	// before the send world's own cleanup, which waits for every stream the stub served
	self.t.Cleanup(self.Sender.Close)
	self.Runner, err = sidecar.NewSmtpOutboxRunner(&sidecar.SmtpOutboxRunnerArgs{
		Sender: self.Sender, Mailbox: mailbox, SidecarId: owner.SidecarId, MemberDeviceKey: memberDeviceKey,
		Consented: func() bool { return true }, OwnCap: self.ProverHost.Cap, Settings: send.Settings, Clock: clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
}

// Runs the client's component (the file header's component row) until the world ends.
func (self *M9World) attach() {
	self.t.Helper()
	owner := self.M8.Owner
	err := self.Owner.Attach(&sidecar.SidecarEnv{
		Ctx:      self.ctx,
		Identity: &sidecar.SidecarIdentity{NetworkId: self.M8.Admission.NetworkId(), SidecarId: owner.SidecarId},
		Store:    sidecartest.NewFakeStore().Root(),
		Log:      sidecar.NewNoopLogger(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
}

// The barrier a pass of the client's ingest reaches once each message it wrote of one depositor's deposits has been
// handed to forwarding: their CONSUME (mail_ingest.go), after every message's callback.
const m9WorldIngestedSite = "mail.ingest.consume.after"

// Runs step, which leaves one depositor's deposits standing in the mailbox, then the client's ingest over them (the file
// header's component row): a wake (MailClient.Resync), and the pass's CONSUME held at its barrier, so the pass has
// written each message and run its forwarding before this returns, then let go. The barrier is armed before step, so a
// pass that a hint starts takes it too. Only with the component, and only for a step that leaves a deposit standing.
func (self *M9World) Ingest(step func()) {
	self.t.Helper()
	barriers := self.M8.Net.Barriers()
	if err := barriers.Arm(m9WorldIngestedSite, "", 0); err != nil {
		self.t.Fatal(err)
	}
	step()
	self.Owner.Resync()
	if err := barriers.AwaitHeld(self.ctx, m9WorldIngestedSite, ""); err != nil {
		self.t.Fatal(err)
	}
	if err := barriers.Release(m9WorldIngestedSite); err != nil {
		self.t.Fatal(err)
	}
}

// Files device's IndexerSet as M8World.Designate does, and keeps the laptop's engine at the tip with M8's.
func (self *M9World) Designate(device *sidecartest.AdmissionDevice, services ...protocol.IndexerService) {
	self.t.Helper()
	self.M8.Designate(device, services...)
	self.install(self.OwnerEngine)
}

// What the world's network and its contexts end with.
func (self *M9World) Context() context.Context {
	return self.ctx
}

// One pass of the prover host's runner over the member's o/.
func (self *M9World) RunOutbox() *sidecar.SmtpOutboxPass {
	self.t.Helper()
	pass, err := self.Runner.RunOnce(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	return pass
}

// The outcomes the member's or/ holds for effectKey, as the composing device reads them through its own mailbox: by
// domain, none where or/ holds none.
func (self *M9World) Outcomes(effectKey []byte) map[string]*sidecar.SmtpDomainOutcome {
	self.t.Helper()
	mailbox, err := self.Owner.SmtpMailbox()
	if err != nil {
		self.t.Fatal(err)
	}
	outcomes, err := mailbox.ReadOutcomes(self.ctx, effectKey)
	if errors.Is(err, sidecar.ErrSmtpMailboxNotFound) {
		return map[string]*sidecar.SmtpDomainOutcome{}
	}
	if err != nil {
		self.t.Fatal(err)
	}
	byDomain := map[string]*sidecar.SmtpDomainOutcome{}
	for _, outcome := range outcomes {
		byDomain[outcome.Domain] = outcome
	}
	return byDomain
}

// The effect keys the member's o/ holds, sorted.
func (self *M9World) Outbox() [][]byte {
	self.t.Helper()
	mailbox, err := self.Owner.SmtpMailbox()
	if err != nil {
		self.t.Fatal(err)
	}
	effectKeys, err := mailbox.ListOutbox(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	slices.SortFunc(effectKeys, bytes.Compare)
	return effectKeys
}

// Every mail_send event the prover host's sender raised.
func (self *M9World) MailSendEvents() []sidecar.SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// A recipient domain whose one MX, at address, serves script, authenticated to TL3 under the world's PKI or, with
// authenticated false, reachable only at TL4 (SmtpSendWorld.AddDomain).
func (self *M9World) AddDomain(domain string, address netip.Addr, script *sidecartest.MxScript, authenticated bool) *sidecartest.ScriptedMx {
	self.t.Helper()
	return self.Send.AddDomain(domain, "mx."+domain, address, script, authenticated)
}

// A burner's domain under the network's zone, <blabel>.<net>.<root>.
func (self *M9World) BurnerDomain(label string) string {
	return label + "." + self.M8.Zone()
}

// Each call POST /smtp/dkim-keys took, answered as the server answers one it applies: every selector it named, echoed.
// Safe for concurrent use.
type M9WorldDkim struct {
	stateLock sync.Mutex
	calls     []*sidecar.SmtpDkimKeysArgs
}

func (self *M9WorldDkim) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	result := &sidecar.SmtpDkimKeysResult{Published: []string{}, Retired: []string{}}
	for _, publish := range args.Publish {
		result.Published = append(result.Published, publish.Selector)
	}
	for _, retire := range args.Retire {
		result.Retired = append(result.Retired, retire.Selector)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, args)
	return result, nil
}

// Every call so far.
func (self *M9WorldDkim) Calls() []*sidecar.SmtpDkimKeysArgs {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls)
}

// The selectors published for domain so far, in order.
func (self *M9WorldDkim) Published(domain string) []*sidecar.SmtpDkimKeyPublish {
	published := []*sidecar.SmtpDkimKeyPublish{}
	for _, call := range self.Calls() {
		for _, publish := range call.Publish {
			if strings.EqualFold(publish.Domain, domain) {
				published = append(published, publish)
			}
		}
	}
	return published
}

// What sending binds on the laptop's client beside M8's binding (the file header's client row).
type m8SendingParts struct {
	sign      func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error)
	standing  func(ctx context.Context) (*sidecar.AbuseStatus, error)
	selectors sidecar.MailBurnerSelectors
}

// A client of device bound as M8World.MailClient binds one, on engine and settings, with parts' sending binding.
func (self *M8World) sendingClient(device *sidecartest.AdmissionDevice, engine *sidecar.AclEngine, settings *sidecar.MailSettings, parts *m8SendingParts) *sidecar.MailClient {
	self.t.Helper()
	client, err := sidecar.NewMailClient(&sidecar.MailClientArgs{
		NetworkId: self.Admission.NetworkId(),
		SidecarId: device.SidecarId,
		Store:     sidecartest.NewFakeStore().Root(),
		Settings:  settings,
		Clock:     self.Net.Clock(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	client.Bind(&sidecar.MailBinding{
		Evs:             self.OwnerEvs,
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
		ConfigKey: func(ctx context.Context) (*sidecar.EvsRepoKey, error) {
			return self.ConfigKey, nil
		},
		Sign:            parts.sign,
		Standing:        parts.standing,
		BurnerSelectors: parts.selectors,
	})
	return client
}

// A keychain namespace in memory: the laptop's smtp-dkim namespace of keychain.ur (§5.9).
type m9WorldSecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

func newM9WorldSecrets() *m9WorldSecrets {
	return &m9WorldSecrets{values: map[string][]byte{}}
}

func (self *m9WorldSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *m9WorldSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = bytes.Clone(value)
	return nil
}

func (self *m9WorldSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *m9WorldSecrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.values {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}
