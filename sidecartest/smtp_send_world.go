//go:build !sidecar_http

// SmtpSendWorld: T2's composed outbound path (§14.4, §14.5, D-SMTP-18; SMTP-M9-31), for S6, FS-123 and the privacy
// rows, and for MAIL's M9 rows after them: recipient domains whose MXs are ScriptedMx in an MxWorld behind
// StubSmtpEdge, the device's own DoH a FakeMailZone that agrees with the world, a synthetic web PKI whose leaves the
// authenticated MXs serve (TL3), and one member mailbox, FakeSmtpMailbox, that the member's devices share. Each
// host is one of the member's devices: a phone, which only queues and signs its o/ entries, or a prover host with a
// FakeSmtpProver, its SmtpProverHost, SmtpSender and SmtpOutboxRunner, its own pins, policy and DKIM keys.
//
// Everything runs on one fake clock, so nothing here sleeps. Names are .example, addresses RFC 5737's, and the PKI
// the test's own. Close, through t.Cleanup, closes every sender and joins every stream and MX connection.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a world is built with.
type SmtpSendWorldSettings struct {
	// The stub edge's settings; nil is DefaultStubSmtpEdgeSettings'.
	Edge *StubSmtpEdgeSettings
	// The verifier's script; nil holds nothing.
	Verifier *FakeSmtpProofScript
	// Changes to DefaultSmtpSenderSettings that every host takes.
	Sender func(settings *sidecar.SmtpSenderSettings)
}

// The envelope sender every host sends as, and the network domain its From and Message-ID name.
const (
	SmtpSendWorldSender        = "bounce-1@b.n1.root.example"
	SmtpSendWorldNetworkDomain = "n1.root.example"
)

// One recipient domain's world.
type SmtpSendWorld struct {
	t        *testing.T
	Clock    *FakeClock
	World    *MxWorld
	Zone     *FakeMailZone
	Edge     *StubSmtpEdge
	Dialer   *StubSmtpEdgeDialer
	Verifier *FakeSmtpProofVerifier
	Mailbox  *FakeSmtpMailbox
	Settings *sidecar.SmtpSenderSettings
	Anchors  *sidecar.SmtpDnssecAnchors
	Roots    *x509.CertPool
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey

	stateLock sync.Mutex
	// the member's admitted devices' identity keys
	devices map[sidecar.Id]ed25519.PublicKey
	hosts   []*SmtpSendHost
	events  []sidecar.SidecarEvent
	notes   []*sidecar.RecordReachNote
}

// One device of the member.
type SmtpSendHost struct {
	SidecarId sidecar.Id
	key       ed25519.PrivateKey
	// Nil on a phone.
	Prover     *FakeSmtpProver
	ProverHost *sidecar.SmtpProverHost
	Sender     *sidecar.SmtpSender
	// Nil on a phone.
	Runner *sidecar.SmtpOutboxRunner
	Pins   *sidecar.SmtpPinStore
}

// A world with no domain yet: AddDomain adds them.
func NewSmtpSendWorld(t *testing.T, settings *SmtpSendWorldSettings) *SmtpSendWorld {
	t.Helper()
	if settings == nil {
		settings = &SmtpSendWorldSettings{}
	}
	clock := NewFakeClock(time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC))
	worldSettings := DefaultMxWorldSettings()
	worldSettings.Clock = clock
	world, err := NewMxWorld(worldSettings)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := sidecar.NewSmtpDnssecAnchors(world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	senderSettings := sidecar.DefaultSmtpSenderSettings()
	if settings.Sender != nil {
		settings.Sender(senderSettings)
	}
	self := &SmtpSendWorld{
		t:        t,
		Clock:    clock,
		World:    world,
		Zone:     NewFakeMailZone(clock),
		Verifier: NewFakeSmtpProofVerifier(settings.Verifier),
		Mailbox:  NewFakeSmtpMailbox(nil),
		Settings: senderSettings,
		Anchors:  anchors,
		devices:  map[sidecar.Id]ed25519.PublicKey{},
	}
	self.rootCert, self.rootKey = self.certificate("Synthetic Send World Root", true, nil, nil)
	self.Roots = x509.NewCertPool()
	self.Roots.AddCert(self.rootCert)
	self.Edge = NewStubSmtpEdge(world, world, self.Verifier, settings.Edge)
	self.Dialer = self.Edge.Dialer()
	t.Cleanup(func() {
		for _, host := range self.hostList() {
			host.Sender.Close()
		}
		self.Dialer.Wait()
		world.Wait()
	})
	return self
}

// A certificate for name under issuer, the root itself when issuer is nil.
func (self *SmtpSendWorld) certificate(name string, isCa bool, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	self.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		self.t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCa,
	}
	if isCa {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.ExtKeyUsage = nil
	} else {
		template.DNSNames = []string{name}
	}
	if issuer == nil {
		issuer, issuerKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		self.t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		self.t.Fatal(err)
	}
	return certificate, key
}

// Adds domain, signed, whose one MX host at address serves script: under a leaf of the world's PKI that the
// device's own DoH agrees with when authenticated, which reaches TL3, else under a self-signed certificate the DoH
// does not name, which reaches only TL4.
func (self *SmtpSendWorld) AddDomain(domain string, host string, address netip.Addr, script *MxScript, authenticated bool) *ScriptedMx {
	self.t.Helper()
	if err := self.World.AddZone(domain, nil); err != nil {
		self.t.Fatal(err)
	}
	if err := self.World.SetMx(domain, &sidecar.SmtpMxHost{Preference: 10, Host: host}); err != nil {
		self.t.Fatal(err)
	}
	mxSettings := DefaultScriptedMxSettings()
	if authenticated {
		leaf, key := self.certificate(host, false, self.rootCert, self.rootKey)
		mxSettings.Certificate = &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
		self.Zone.AddMx(domain, 10, host)
	}
	mx, err := NewScriptedMx(host, script, mxSettings)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.World.AddMx(host, address, mx); err != nil {
		self.t.Fatal(err)
	}
	return mx
}

// An MX script that offers no CHUNKING after TLS, so a send to it goes in DATA.
func SmtpDataOnlyMxScript() *MxScript {
	script := DefaultMxScript()
	script.Keywords = []string{"PIPELINING", "SIZE 52428800", "8BITMIME"}
	return script
}

func (self *SmtpSendWorld) hostList() []*SmtpSendHost {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.hosts)
}

// The identity key of an admitted device of the member, nil for any other sidecar.
func (self *SmtpSendWorld) MemberDeviceKey(sidecarId sidecar.Id) ed25519.PublicKey {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.devices[sidecarId]
}

// Takes a device out of the member's admitted devices, as a revocation does.
func (self *SmtpSendWorld) Revoke(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.devices, sidecarId)
}

// Every mail_send event a host raised.
func (self *SmtpSendWorld) MailSendEvents() []sidecar.SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// Every reach note a host made.
func (self *SmtpSendWorld) ReachNotes() []*sidecar.RecordReachNote {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.notes)
}

// A device of the member: a prover host whose FakeSmtpProver proves up to dataProofByteCount octets of DATA, its p/
// written by one idle step, or with proverSettings nil a phone, which only queues. log, when set, is every part's
// logger. hold may be nil.
func (self *SmtpSendWorld) AddHost(proverSettings *FakeSmtpProverSettings, hold *sidecar.SmtpStatusHold, log sidecar.Logger) *SmtpSendHost {
	self.t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		self.t.Fatal(err)
	}
	host := &SmtpSendHost{SidecarId: sidecar.NewId(), key: key}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.devices[host.SidecarId] = key.Public().(ed25519.PublicKey)
	}()
	store := NewFakeStore()
	host.Pins = sidecar.NewSmtpPinStore(store.Root(), self.Settings, self.Clock, log)
	policy := sidecar.NewSmtpTlsPolicy(
		sidecar.NewSmtpDane(self.Anchors, self.Clock, nil),
		sidecar.NewSmtpMtaSts(self.Zone, self.World.MtaStsTransport(), store.Root(), self.Settings, self.Clock),
		host.Pins, sidecar.NewSmtpTlsAllowanceStore(store.Root(), self.Settings, self.Clock), nil, self.Zone, self.Roots,
		self.Settings, self.Clock)
	args := &sidecar.SmtpSenderArgs{
		Dialer:       self.Dialer,
		Policy:       policy,
		Pins:         host.Pins,
		Dkim:         sidecar.NewSmtpDkimKeys(newSmtpSendWorldSecrets(), smtpSendWorldPublisher{}, self.Settings, self.Clock, log),
		Mailbox:      self.Mailbox,
		MemberDevice: func(sidecarId sidecar.Id) bool { return self.MemberDeviceKey(sidecarId) != nil },
		Reach: func(note *sidecar.RecordReachNote) error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.notes = append(self.notes, note)
			return nil
		},
		ReachGrant: func(message *sidecar.SmtpOutboundMessage) *sidecar.SmtpReachGrant {
			return &sidecar.SmtpReachGrant{GrantId: bytes.Repeat([]byte{0x9a}, 32), PolicyVersion: 1}
		},
		Events: func(event sidecar.SidecarEvent) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.events = append(self.events, event)
		},
		Settings: self.Settings,
		Clock:    self.Clock,
		Log:      log,
	}
	if proverSettings != nil {
		if proverSettings.Measure == nil {
			proverSettings.Measure = &sidecar.SmtpProverMeasure{
				DataProofBytes: proverSettings.DataProofByteCount, DataBytesPerSecond: 512, MeasureTime: self.Clock.Now(), UnitTime: 5 * time.Second,
				HeadByteCount: 831, HeaderRecordByteCount: 1199, EnvelopeGroupCount: 13,
			}
		}
		host.Prover = NewFakeSmtpProver(proverSettings)
		proverHost, err := sidecar.NewSmtpProverHost(&sidecar.SmtpProverHostArgs{
			Prover: host.Prover, Mailbox: self.Mailbox, SidecarId: host.SidecarId, MailEnabled: func() bool { return true },
			Settings: self.Settings, Clock: self.Clock, Log: log,
		})
		if err != nil {
			self.t.Fatal(err)
		}
		if err := proverHost.Idle(context.Background()); err != nil {
			self.t.Fatal(err)
		}
		host.ProverHost = proverHost
		args.Prover = host.Prover
		args.Measure = proverHost.Measure
		args.ReadyKeySets = proverHost.ReadyKeySets
		args.SendHold = proverHost.HoldForSend
	}
	sender, err := sidecar.NewSmtpSender(args)
	if err != nil {
		self.t.Fatal(err)
	}
	host.Sender = sender
	if proverSettings != nil {
		host.Runner, err = sidecar.NewSmtpOutboxRunner(&sidecar.SmtpOutboxRunnerArgs{
			Sender: sender, Mailbox: self.Mailbox, SidecarId: host.SidecarId, MemberDeviceKey: self.MemberDeviceKey,
			Consented: func() bool { return true }, Hold: hold, OwnCap: host.ProverHost.Cap, Settings: self.Settings,
			Clock: self.Clock, Log: log,
		})
		if err != nil {
			self.t.Fatal(err)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.hosts = append(self.hosts, host)
	}()
	return host
}

// A prover host's settings whose DATA cap is dataProofByteCount octets.
func SmtpSendWorldProver(dataProofByteCount uint64) *FakeSmtpProverSettings {
	settings := DefaultFakeSmtpProverSettings()
	settings.DataProofByteCount = dataProofByteCount
	return settings
}

// §6.9's Signed by the host's identity key, as Sidecar.Sign would make it.
func (self *SmtpSendHost) Sign(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      body,
		SignerId:  self.SidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// A message to recipients, its Bcc header naming bcc, From alice at the network domain under fromName, with subject
// and body.
func (self *SmtpSendWorld) Message(recipients []string, bcc []string, fromName string, subject string, body string) *sidecar.SmtpOutboundMessage {
	effectKey := make([]byte, 32)
	rand.Read(effectKey)
	from := "<alice@" + SmtpSendWorldNetworkDomain + ">"
	if fromName != "" {
		from = fromName + " " + from
	}
	text := "From: " + from + "\r\n" + "To: " + strings.Join(recipients, ", ") + "\r\n"
	if 0 < len(bcc) {
		text += "Bcc: " + strings.Join(bcc, ", ") + "\r\n"
	}
	text += "Subject: " + subject + "\r\n" +
		"Message-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@" + SmtpSendWorldNetworkDomain + ">\r\n" +
		"\r\n" + body
	return &sidecar.SmtpOutboundMessage{
		EffectKey:  effectKey,
		SendId:     sidecar.NewId(),
		Sender:     SmtpSendWorldSender,
		Recipients: append(slices.Clone(recipients), bcc...),
		Message:    []byte(text),
		CreateTime: self.Clock.Now(),
	}
}

// Queues message at o/ as the composing device writes it (§15.10's step 4), signed by host.
func (self *SmtpSendWorld) Queue(host *SmtpSendHost, message *sidecar.SmtpOutboundMessage) {
	self.t.Helper()
	signed, err := sidecar.SignSmtpOutboxEntry(message, host.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	if !self.Mailbox.PutOutbox(message.EffectKey, signed, message.Message) {
		self.t.Fatal("o/ held the entry already")
	}
}

// One outbox pass of host.
func (self *SmtpSendWorld) RunOnce(host *SmtpSendHost) *sidecar.SmtpOutboxPass {
	self.t.Helper()
	pass, err := host.Runner.RunOnce(context.Background())
	if err != nil {
		self.t.Fatal(err)
	}
	return pass
}

// The outcome or/ holds for domain of message, nil for none.
func (self *SmtpSendWorld) Outcome(message *sidecar.SmtpOutboundMessage, domain string) *sidecar.SmtpDomainOutcome {
	self.t.Helper()
	outcomes, err := self.Mailbox.ReadOutcomes(context.Background(), message.EffectKey)
	if err != nil {
		return nil
	}
	for _, outcome := range outcomes {
		if outcome.Domain == domain {
			return outcome
		}
	}
	return nil
}

// A keychain namespace in memory.
type smtpSendWorldSecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

func newSmtpSendWorldSecrets() *smtpSendWorldSecrets {
	return &smtpSendWorldSecrets{values: map[string][]byte{}}
}

func (self *smtpSendWorldSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *smtpSendWorldSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = bytes.Clone(value)
	return nil
}

func (self *smtpSendWorldSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *smtpSendWorldSecrets) List(prefix string) ([]string, error) {
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

// POST /smtp/dkim-keys answering every publish and retire.
type smtpSendWorldPublisher struct{}

func (self smtpSendWorldPublisher) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	result := &sidecar.SmtpDkimKeysResult{}
	for _, publish := range args.Publish {
		result.Published = append(result.Published, publish.Selector)
	}
	for _, retire := range args.Retire {
		result.Retired = append(result.Retired, retire.Selector)
	}
	return result, nil
}
