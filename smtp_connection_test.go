//go:build !sidecar_http && !ios_extension

// The connection driver (SMTP-M9-07) on FakeSmtpProver, StubSmtpEdge and ScriptedMx in testTlsWorld's MX world:
// each preamble code maps as §14.4 has it and a code of 0 resets the stream; a stream that ends before its answer
// goes to the backup ticket; a cancelled send ends and its sender's Close joins it; KEYS is a hold, an empty key set
// makes no connection, and EnvelopeRetry comes back to the sender; the preamble is answered before the first TLS
// byte, by the barriers; and no sender file dials TCP. The engine's own run of the driver is SMTP-M9-31's
// (smtpedgeservice), since only that package reaches the engine's per-stream entry.
//
// Names are .example and addresses RFC 5737's.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	testSenderAddress   = "bounce-1@b.n1.root.example"
	testSenderMessageId = "qvsc2zbwd5c3m5rbnvzxjzpnay@n1.root.example"
)

// A keychain namespace in memory.
type testMemorySecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

func newTestMemorySecrets() *testMemorySecrets {
	return &testMemorySecrets{values: map[string][]byte{}}
}

func (self *testMemorySecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *testMemorySecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = bytes.Clone(value)
	return nil
}

func (self *testMemorySecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *testMemorySecrets) List(prefix string) ([]string, error) {
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
type testEchoDkimPublisher struct{}

func (self testEchoDkimPublisher) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	result := &sidecar.SmtpDkimKeysResult{}
	for _, publish := range args.Publish {
		result.Published = append(result.Published, publish.Selector)
	}
	for _, retire := range args.Retire {
		result.Retired = append(result.Retired, retire.Selector)
	}
	return result, nil
}

// What a sender world is built with, each nil field its default.
type testSenderOptions struct {
	script         *sidecartest.MxScript
	prover         *sidecartest.FakeSmtpProverSettings
	noProver       bool
	edge           *sidecartest.StubSmtpEdgeSettings
	verifierScript *sidecartest.FakeSmtpProofScript
	settings       func(settings *sidecar.SmtpSenderSettings)
	// replaces the stub's dialer, given it
	dialer       func(stub *sidecartest.StubSmtpEdgeDialer) sidecar.SmtpEdgeDialer
	readyKeySets [][]byte
	measure      *sidecar.SmtpProverMeasure
	memberDevice func(sidecarId sidecar.Id) bool
	// replaces the world's DKIM keys, given its device DoH, clock and settings
	dkim func(zone *sidecartest.FakeMailZone, clock *sidecartest.FakeClock, settings *sidecar.SmtpSenderSettings) *sidecar.SmtpDkimKeys
}

// mail.example and its MX behind the stub edge, a sender on the fake prover, and what it reported.
type testSenderWorld struct {
	t        *testing.T
	tls      *testTlsWorld
	mx       *sidecartest.ScriptedMx
	verifier *sidecartest.FakeSmtpProofVerifier
	edge     *sidecartest.StubSmtpEdge
	stub     *sidecartest.StubSmtpEdgeDialer
	prover   *sidecartest.FakeSmtpProver
	mailbox  *sidecartest.FakeSmtpMailbox
	pins     *sidecar.SmtpPinStore
	settings *sidecar.SmtpSenderSettings
	sender   *sidecar.SmtpSender

	stateLock sync.Mutex
	events    []sidecar.SidecarEvent
	notes     []*sidecar.RecordReachNote
}

func newTestSenderWorld(t *testing.T, options *testSenderOptions) *testSenderWorld {
	t.Helper()
	if options == nil {
		options = &testSenderOptions{}
	}
	tls := newTestTlsWorld(t, nil)
	self := &testSenderWorld{t: t, tls: tls, settings: tls.settings}
	if options.settings != nil {
		options.settings(self.settings)
	}
	self.mx = self.addDomain(testTlsDomain, testTlsHost, testTlsAddress, options.script)
	self.verifier = sidecartest.NewFakeSmtpProofVerifier(options.verifierScript)
	self.edge = sidecartest.NewStubSmtpEdge(tls.world, tls.world, self.verifier, options.edge)
	self.stub = self.edge.Dialer()
	var dialer sidecar.SmtpEdgeDialer = self.stub
	if options.dialer != nil {
		dialer = options.dialer(self.stub)
	}
	var prover sidecar.SmtpProver
	if !options.noProver {
		self.prover = sidecartest.NewFakeSmtpProver(options.prover)
		prover = self.prover
	}
	self.mailbox = sidecartest.NewFakeSmtpMailbox(nil)
	self.pins = sidecar.NewSmtpPinStore(tls.store.Root(), self.settings, tls.clock, nil)
	mtaSts := sidecar.NewSmtpMtaSts(tls.zone, tls.world.MtaStsTransport(), tls.store.Root(), self.settings, tls.clock)
	dane := sidecar.NewSmtpDane(tls.anchors, tls.clock, nil)
	allowances := sidecar.NewSmtpTlsAllowanceStore(tls.store.Root(), self.settings, tls.clock)
	policy := sidecar.NewSmtpTlsPolicy(dane, mtaSts, self.pins, allowances, tls.gate, tls.zone, tls.pki.roots, self.settings, tls.clock)
	dkim := sidecar.NewSmtpDkimKeys(newTestMemorySecrets(), testEchoDkimPublisher{}, self.settings, tls.clock, nil)
	if options.dkim != nil {
		dkim = options.dkim(tls.zone, tls.clock, self.settings)
	}
	args := &sidecar.SmtpSenderArgs{
		Dialer:       dialer,
		Prover:       prover,
		Policy:       policy,
		Pins:         self.pins,
		Dkim:         dkim,
		Mailbox:      self.mailbox,
		MemberDevice: options.memberDevice,
		Reach: func(note *sidecar.RecordReachNote) error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.notes = append(self.notes, note)
			return nil
		},
		ReachGrant: func(message *sidecar.SmtpOutboundMessage) *sidecar.SmtpReachGrant {
			return &sidecar.SmtpReachGrant{GrantId: bytes.Repeat([]byte{0x9a}, 32), PolicyVersion: 3}
		},
		Events: func(event sidecar.SidecarEvent) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.events = append(self.events, event)
		},
		Settings: self.settings,
		Clock:    tls.clock,
	}
	if options.readyKeySets != nil {
		readyKeySets := options.readyKeySets
		args.ReadyKeySets = func() [][]byte { return readyKeySets }
	}
	if options.measure != nil {
		measure := options.measure
		args.Measure = func() *sidecar.SmtpProverMeasure { return measure }
	}
	sender, err := sidecar.NewSmtpSender(args)
	if err != nil {
		t.Fatal(err)
	}
	self.sender = sender
	t.Cleanup(func() {
		sender.Close()
		self.stub.Wait()
		tls.world.Wait()
	})
	return self
}

// domain, whose one MX is host at address, serving a leaf of the test's PKI under script, which the device's own DoH
// agrees with: TL3.
func (self *testSenderWorld) addDomain(domain string, host string, address netip.Addr, script *sidecartest.MxScript) *sidecartest.ScriptedMx {
	self.t.Helper()
	if domain != testTlsDomain && domain != testTlsOtherZone {
		if err := self.tls.world.AddZone(domain, nil); err != nil {
			self.t.Fatal(err)
		}
	}
	if err := self.tls.world.SetMx(domain, &sidecar.SmtpMxHost{Preference: 10, Host: host}); err != nil {
		self.t.Fatal(err)
	}
	settings := sidecartest.DefaultScriptedMxSettings()
	settings.Certificate = self.tls.pki.leaf(self.t, host)
	mx, err := sidecartest.NewScriptedMx(host, script, settings)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.tls.world.AddMx(host, address, mx); err != nil {
		self.t.Fatal(err)
	}
	if domain != testTlsDomain {
		self.tls.zone.AddMx(domain, 10, host)
	}
	return mx
}

// A message to recipients, From alice at n1.root.example, its Bcc header naming bcc.
func (self *testSenderWorld) message(recipients []string, bcc []string, body string) *sidecar.SmtpOutboundMessage {
	effectKey := make([]byte, 32)
	rand.Read(effectKey)
	text := "From: Alice Example <alice@n1.root.example>\r\n" +
		"To: " + strings.Join(recipients, ", ") + "\r\n"
	if 0 < len(bcc) {
		text += "Bcc: " + strings.Join(bcc, ", ") + "\r\n"
	}
	text += "Subject: A synthetic message\r\n" +
		"Message-ID: <" + testSenderMessageId + ">\r\n" +
		"\r\n" + body
	return &sidecar.SmtpOutboundMessage{
		EffectKey:  effectKey,
		SendId:     sidecar.NewId(),
		Sender:     testSenderAddress,
		Recipients: append(slices.Clone(recipients), bcc...),
		Message:    []byte(text),
		CreateTime: self.tls.clock.Now(),
	}
}

// One send, checked to have no error, and its outcome for domain.
func (self *testSenderWorld) send(message *sidecar.SmtpOutboundMessage) *sidecar.SmtpSendResult {
	self.t.Helper()
	result, err := self.sender.Send(context.Background(), message)
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

// The outcome result holds for domain.
func testDomainOutcome(t *testing.T, result *sidecar.SmtpSendResult, domain string) *sidecar.SmtpDomainOutcome {
	t.Helper()
	for _, outcome := range result.Domains {
		if outcome.Domain == domain {
			return outcome
		}
	}
	t.Fatalf("no outcome for %s in %+v", domain, result.Domains)
	return nil
}

func (self *testSenderWorld) reachNotes() []*sidecar.RecordReachNote {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.notes)
}

func (self *testSenderWorld) mailSendEvents() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, event := range self.events {
		if event.Kind == sidecar.SidecarEventMailSend {
			count += 1
		}
	}
	return count
}

// The connection args for one message to bob at mail.example, as Send would build them.
func (self *testSenderWorld) connectionArgs(message *sidecar.SmtpOutboundMessage, keySet []byte) *sidecar.SmtpConnectionArgsForTest {
	self.t.Helper()
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{
		Message:          message.Message,
		HeaderFromDomain: "n1.root.example",
		MessageIdDomain:  "n1.root.example",
		Now:              self.tls.clock.Now(),
		Settings:         self.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return &sidecar.SmtpConnectionArgsForTest{
		EffectKey:       message.EffectKey,
		Wire:            wire,
		SenderAddress:   message.Sender,
		RecipientDomain: testTlsDomain,
		RecipientLocals: []string{"bob"},
		Mode:            sidecar.SmtpModeBdat,
		KeySet:          keySet,
	}
}

// A send through the stub: sent at TL3, the MX's one transaction from the envelope sender to bob, the mode pinned for
// the domain, the SmtpOutcome handed to the edge after the stream, and no reset.
func TestSmtpConnectionSendsThroughTheStub(t *testing.T) {
	world := newTestSenderWorld(t, nil)
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "A body line.\r\n")
	result := world.sender.RunConnectionForTest(context.Background(), world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet()))
	if result.Err != nil || result.Proof == nil || !result.Proof.Accepted {
		t.Fatalf("not sent: %+v %v", result.Proof, result.Err)
	}
	if result.PreambleCode != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK || result.TlsLevel != sidecar.SmtpTlsLevelIndependentMx || result.EdgeResetCount != 0 {
		t.Errorf("code %s, level %d, resets %d", result.PreambleCode, result.TlsLevel, result.EdgeResetCount)
	}
	if len(result.SendId) != sidecar.SmtpSendIdByteCount || result.MxHost != testTlsHost {
		t.Errorf("issued %x at %s", result.SendId, result.MxHost)
	}
	transactions := world.mx.Transactions()
	if len(transactions) != 1 || transactions[0].Sender != "<"+testSenderAddress+">" || !slices.Equal(transactions[0].Recipients, []string{"<bob@" + testTlsDomain + ">"}) {
		t.Fatalf("transactions %+v", transactions)
	}
	// the preamble declared the signed message's own length, and named the key set and a selector
	preamble := world.edge.Preambles()[0]
	if preamble.GetMessageByteCount() != uint64(len(transactions[0].Message)) || !bytes.Equal(preamble.GetProofKeySet(), sidecartest.FakeSmtpProverKeySet()) ||
		len(preamble.GetDkimSelector()) != sidecar.SmtpDkimSelectorLength || preamble.GetRecipientCount() != 1 {
		t.Errorf("preamble %v", preamble)
	}
	if mode, err := world.pins.DomainMode(testTlsDomain); err != nil || mode != sidecar.SmtpModeBdat {
		t.Errorf("the domain's mode %d, %v", mode, err)
	}
	outcomes := world.edge.Outcomes()
	if len(outcomes) != 1 || !bytes.Equal(outcomes[0].GetSendId(), result.SendId) || outcomes[0].GetTlsLevel() != 3 || outcomes[0].GetMode() != 1 ||
		len(outcomes[0].GetReplyCodes()) == 0 || !result.OutcomeSent {
		t.Errorf("outcomes %v", outcomes)
	}
}

// HALTED, QUOTA and TRY_LATER hold with retry_after_ms; NO_MX, NO_TLS and DENIED end; KEYS is a hold, KeysRefused;
// none of them reaches the prover.
func TestSmtpConnectionMapsEachPreambleCode(t *testing.T) {
	for _, code := range []protocol.SmtpPreambleCode{
		protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA,
		protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX,
		protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED,
		protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS,
	} {
		edgeSettings := sidecartest.DefaultStubSmtpEdgeSettings()
		edgeSettings.Code = code
		edgeSettings.RetryAfter = 90 * time.Second
		world := newTestSenderWorld(t, &testSenderOptions{edge: edgeSettings})
		message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
		result := world.sender.RunConnectionForTest(context.Background(), world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet()))
		if result.PreambleCode != code || result.Proof != nil || len(world.prover.Sends()) != 0 || len(world.tls.world.Dials()) != 0 {
			t.Errorf("%s: answered %s, proof %+v, %d sends", code, result.PreambleCode, result.Proof, len(world.prover.Sends()))
		}
		held := code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED || code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA ||
			code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER
		if held != (result.RetryAfterMillis == 90_000) {
			t.Errorf("%s: retry after %d", code, result.RetryAfterMillis)
		}
		if (code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS) != result.KeysRefused {
			t.Errorf("%s: keys refused %v", code, result.KeysRefused)
		}
		if result.MailMayHaveGone() {
			t.Errorf("%s: a refusal before the MX counted as a unit", code)
		}
	}
}

// The far end of a test stream: reads the preamble, then does what it was made to.
type testScriptedEdgeStream struct {
	net.Conn
	stateLock sync.Mutex
	aborted   bool
}

func (self *testScriptedEdgeStream) ProofChannel(sendId []byte) sidecar.SmtpProofChannel {
	return nil
}

func (self *testScriptedEdgeStream) SendOutcome(ctx context.Context, outcome *protocol.SmtpOutcome) error {
	return nil
}

func (self *testScriptedEdgeStream) Abort() error {
	self.stateLock.Lock()
	self.aborted = true
	self.stateLock.Unlock()
	return self.Conn.Close()
}

func (self *testScriptedEdgeStream) wasAborted() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.aborted
}

// A dialer whose first streams' far ends act out serves, in order, then hands every later dial to next.
type testScriptedEdgeDialer struct {
	serves  []func(conn net.Conn)
	next    sidecar.SmtpEdgeDialer
	serving sync.WaitGroup

	stateLock sync.Mutex
	streams   []*testScriptedEdgeStream
	dialCount int
}

func (self *testScriptedEdgeDialer) DialSmtpEdge(ctx context.Context) (sidecar.SmtpEdgeStream, error) {
	self.stateLock.Lock()
	index := self.dialCount
	self.dialCount += 1
	self.stateLock.Unlock()
	if len(self.serves) <= index {
		return self.next.DialSmtpEdge(ctx)
	}
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	stream := &testScriptedEdgeStream{Conn: sidecarEnd}
	self.stateLock.Lock()
	self.streams = append(self.streams, stream)
	self.stateLock.Unlock()
	self.serving.Add(1)
	go func() {
		defer self.serving.Done()
		defer edgeEnd.Close()
		self.serves[index](edgeEnd)
	}()
	return stream, nil
}

// A code of 0 resets the stream as §6.11's protocol error, and is no reset worth the backup ticket.
func TestSmtpConnectionResetsOnACodeOfZero(t *testing.T) {
	var scripted *testScriptedEdgeDialer
	world := newTestSenderWorld(t, &testSenderOptions{dialer: func(stub *sidecartest.StubSmtpEdgeDialer) sidecar.SmtpEdgeDialer {
		scripted = &testScriptedEdgeDialer{next: stub, serves: []func(conn net.Conn){func(conn net.Conn) {
			if _, err := sidecar.ReadSmtpPreamble(conn, nil); err != nil {
				return
			}
			body, _ := proto.Marshal(&protocol.SmtpPreambleResult{Code: 0, RetryAfterMs: 1})
			sidecar.WriteSmtpFrame(conn, &sidecar.SmtpFrame{Type: protocol.MessageType_SMTP_PREAMBLE_RESULT, Body: body}, nil)
			buffer := make([]byte, 1)
			conn.Read(buffer)
		}}}
		return scripted
	}})
	defer scripted.serving.Wait()
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	result := world.sender.RunConnectionForTest(context.Background(), world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet()))
	if !errors.Is(result.Err, sidecar.ErrSmtpFrameProtocol) || result.PreambleCode != protocol.SmtpPreambleCode_SMTP_PREAMBLE_CODE_UNSPECIFIED || result.EdgeResetCount != 0 {
		t.Fatalf("result %+v", result)
	}
	if !scripted.streams[0].wasAborted() || scripted.dialCount != 1 || len(world.prover.Sends()) != 0 {
		t.Errorf("aborted %v after %d dials, %d sends", scripted.streams[0].wasAborted(), scripted.dialCount, len(world.prover.Sends()))
	}
}

// An edge that ends its stream before it answers, as a crash does: the next dial reaches the backup ticket, which
// sends.
func TestSmtpConnectionTakesTheBackupTicketAfterAnEdgeReset(t *testing.T) {
	var scripted *testScriptedEdgeDialer
	world := newTestSenderWorld(t, &testSenderOptions{dialer: func(stub *sidecartest.StubSmtpEdgeDialer) sidecar.SmtpEdgeDialer {
		scripted = &testScriptedEdgeDialer{next: stub, serves: []func(conn net.Conn){func(conn net.Conn) {
			sidecar.ReadSmtpPreamble(conn, nil)
		}}}
		return scripted
	}})
	defer scripted.serving.Wait()
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	result := world.sender.RunConnectionForTest(context.Background(), world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet()))
	if result.Err != nil || result.Proof == nil || !result.Proof.Accepted || result.EdgeResetCount != 1 {
		t.Fatalf("result %+v", result)
	}
	if scripted.dialCount != 2 || world.stub.DialCount() != 1 || len(world.mx.Transactions()) != 1 {
		t.Errorf("%d dials, %d to the stub, %d transactions", scripted.dialCount, world.stub.DialCount(), len(world.mx.Transactions()))
	}

	// two crashes: one backup, then the send holds
	var crashing *testScriptedEdgeDialer
	world = newTestSenderWorld(t, &testSenderOptions{dialer: func(stub *sidecartest.StubSmtpEdgeDialer) sidecar.SmtpEdgeDialer {
		crash := func(conn net.Conn) { sidecar.ReadSmtpPreamble(conn, nil) }
		crashing = &testScriptedEdgeDialer{next: stub, serves: []func(conn net.Conn){crash, crash}}
		return crashing
	}})
	defer crashing.serving.Wait()
	message = world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	result = world.sender.RunConnectionForTest(context.Background(), world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet()))
	if result.Err == nil || result.EdgeResetCount != 1 || crashing.dialCount != 2 || world.stub.DialCount() != 0 {
		t.Errorf("result %+v after %d dials", result, crashing.dialCount)
	}
}

// A prover that blocks inside SendSmtp until its stream ends, as a 2 h DATA send would.
type testBlockingProver struct {
	*sidecartest.FakeSmtpProver
	started chan struct{}
}

func (self *testBlockingProver) SendSmtp(ctx context.Context, conn net.Conn, job *sidecar.SmtpProofJob, channel sidecar.SmtpProofChannel) (*sidecar.SmtpProofResult, error) {
	close(self.started)
	buffer := make([]byte, 1)
	_, err := conn.Read(buffer)
	return nil, err
}

// A send cancelled from outside ends, its stream reset under the prover, and Close joins every send.
func TestSmtpConnectionCancelledSendJoins(t *testing.T) {
	world := newTestSenderWorld(t, nil)
	blocking := &testBlockingProver{FakeSmtpProver: world.prover, started: make(chan struct{})}
	sender, err := sidecar.NewSmtpSender(&sidecar.SmtpSenderArgs{
		Dialer:   world.stub,
		Prover:   blocking,
		Policy:   sidecar.NewSmtpTlsPolicy(sidecar.NewSmtpDane(world.tls.anchors, world.tls.clock, nil), sidecar.NewSmtpMtaSts(world.tls.zone, world.tls.world.MtaStsTransport(), world.tls.store.Root(), world.settings, world.tls.clock), world.pins, sidecar.NewSmtpTlsAllowanceStore(world.tls.store.Root(), world.settings, world.tls.clock), world.tls.gate, world.tls.zone, world.tls.pki.roots, world.settings, world.tls.clock),
		Pins:     world.pins,
		Dkim:     sidecar.NewSmtpDkimKeys(newTestMemorySecrets(), testEchoDkimPublisher{}, world.settings, world.tls.clock, nil),
		Mailbox:  world.mailbox,
		Settings: world.settings,
		Clock:    world.tls.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	sent := make(chan *sidecar.SmtpSendResult, 1)
	go func() {
		result, _ := sender.Send(context.Background(), message)
		sent <- result
	}()
	<-blocking.started
	sender.Close()
	result := <-sent
	if result == nil || testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeDeferred {
		t.Errorf("a cancelled send reported %+v", result)
	}
	if _, err := sender.Send(context.Background(), message); !errors.Is(err, sidecar.ErrSmtpSenderClosed) {
		t.Errorf("a closed sender sent: %v", err)
	}
}

// An empty key set makes no connection and reports no prover.
func TestSmtpConnectionWithNoKeySetDialsNothing(t *testing.T) {
	world := newTestSenderWorld(t, nil)
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	result := world.sender.RunConnectionForTest(context.Background(), world.connectionArgs(message, nil))
	if !result.NoProver || world.stub.DialCount() != 0 || len(world.edge.Preambles()) != 0 {
		t.Errorf("result %+v after %d dials", result, world.stub.DialCount())
	}
}

// The prover's EnvelopeRetry comes back to the sender with the send_id the retry names, after MAIL went.
func TestSmtpConnectionReturnsEnvelopeRetry(t *testing.T) {
	proverSettings := sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.EnvelopeRetry = func(job *sidecar.SmtpProofJob) bool { return job.EnvelopeGroupMaxCount == 0 }
	world := newTestSenderWorld(t, &testSenderOptions{prover: proverSettings})
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	result := world.sender.RunConnectionForTest(context.Background(), world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet()))
	if result.Proof == nil || !result.Proof.EnvelopeRetry || len(result.SendId) == 0 || !result.MailMayHaveGone() || len(world.mx.Transactions()) != 0 {
		t.Fatalf("result %+v", result)
	}
	args := world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet())
	args.EnvelopeGroupMaxCount = 1
	args.RetryOfSendId = result.SendId
	retried := world.sender.RunConnectionForTest(context.Background(), args)
	if retried.Proof == nil || !retried.Proof.Accepted || !bytes.Equal(world.edge.Preambles()[1].GetRetryOfSendId(), result.SendId) {
		t.Errorf("the retry %+v", retried)
	}
	if sends := world.prover.Sends(); len(sends) != 2 || len(world.mx.Transactions()) != 1 {
		t.Errorf("%d sends, %d transactions", len(sends), len(world.mx.Transactions()))
	}
}

// The barriers: the preamble is answered, and SendSmtp about to start, before the MX sees any TLS byte.
func TestSmtpConnectionBarriersOrderThePreambleBeforeTls(t *testing.T) {
	if !sidecartest.HooksLinked {
		t.Skip("the barriers need sidecar_testhooks")
	}
	world := newTestSenderWorld(t, nil)
	type seen struct {
		name          string
		preambleCount int
		secureCount   int
	}
	var seenLock sync.Mutex
	seens := []seen{}
	remove, err := sidecartest.InstallTestHooks(nil, func(name string, key string) {
		if !strings.HasPrefix(name, "smtp.preamble") && !strings.HasPrefix(name, "smtp.send") {
			return
		}
		secure := 0
		for _, event := range world.mx.Events() {
			if event.Secure {
				secure += 1
			}
		}
		seenLock.Lock()
		defer seenLock.Unlock()
		seens = append(seens, seen{name: name, preambleCount: len(world.edge.Preambles()), secureCount: secure})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	result := world.sender.RunConnectionForTest(context.Background(), world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet()))
	if result.Proof == nil || !result.Proof.Accepted {
		t.Fatalf("not sent: %+v", result)
	}
	seenLock.Lock()
	defer seenLock.Unlock()
	names := []string{}
	for _, s := range seens {
		names = append(names, s.name)
	}
	if !slices.Equal(names, []string{"smtp.preamble", "smtp.send", "smtp.send.after"}) {
		t.Fatalf("barriers %v", names)
	}
	for _, s := range seens[:2] {
		if s.preambleCount != 1 || s.secureCount != 0 {
			t.Errorf("%s: %d preambles, %d commands inside TLS", s.name, s.preambleCount, s.secureCount)
		}
	}
	if seens[2].secureCount == 0 {
		t.Error("the send went and the MX saw nothing inside TLS")
	}
}

// No file of the sender's dials TCP or names a port: only the edge reaches an MX (R-SMTP-9). The root's import rules
// (check/) keep smtpproof and every engine out of it.
func TestSmtpSenderDialsNoTcp(t *testing.T) {
	files := []string{"smtp_connection.go", "smtp_channel.go", "smtp_sender.go", "smtp_check.go", "smtp_outcome.go", "smtp_retry.go",
		"smtp_dsn.go", "smtp_receipt.go", "smtp_outbox.go", "smtp_prover_host.go", "smtp_status.go"}
	refused := map[string]bool{"Dial": true, "DialTCP": true, "DialTimeout": true, "Dialer": true, "DialContext": true, "ResolveTCPAddr": true, "Listen": true}
	for _, path := range files {
		fileSet := token.NewFileSet()
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		netNames := map[string]bool{}
		for _, spec := range file.Imports {
			importPath, _ := strconv.Unquote(spec.Path.Value)
			if importPath == "net" || importPath == "crypto/tls" || importPath == "net/netip" {
				name := importPath[strings.LastIndex(importPath, "/")+1:]
				if spec.Name != nil {
					name = spec.Name.Name
				}
				netNames[name] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if identifier, ok := selector.X.(*ast.Ident); ok && netNames[identifier.Name] && refused[selector.Sel.Name] {
				t.Errorf("%s: %s.%s at %s", path, identifier.Name, selector.Sel.Name, fileSet.Position(selector.Pos()))
			}
			return true
		})
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), ":25\"") || strings.Contains(string(source), "\":25") {
			t.Errorf("%s names port 25", path)
		}
	}
}
