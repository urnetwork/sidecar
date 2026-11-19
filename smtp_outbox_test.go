//go:build !sidecar_http && !ios_extension

// The outbox on prover hosts (SMTP-M9-09), on testSenderWorld's MX world with one member mailbox the hosts share:
// FS-123's phone half, a phone's entry picked by the rendezvous hash for a host under the cap, left as deferred, and
// sent by a second host whose recorded cap fits; a forged or tampered entry refused; a halted queue held and resumed
// on expiry; or/ written by the sending host read by the composing phone; two hosts racing on one entry sending at
// most twice and keeping one outcome; an entry removed once every outcome is an end and its approval's window has
// passed; and a host that is no consented device taking nothing.
//
// Names are .example and addresses RFC 5737's.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One device of the member: its sidecar id and identity key.
type testOutboxDevice struct {
	sidecarId sidecar.Id
	key       ed25519.PrivateKey
}

func newTestOutboxDevice() *testOutboxDevice {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	return &testOutboxDevice{sidecarId: sidecar.NewId(), key: key}
}

// §6.9's Signed by the device's identity key.
func (self *testOutboxDevice) sign(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      body,
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// The member's admitted, consented devices.
type testOutboxMember struct {
	stateLock sync.Mutex
	devices   map[sidecar.Id]ed25519.PublicKey
}

func (self *testOutboxMember) admit(device *testOutboxDevice) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.devices[device.sidecarId] = device.key.Public().(ed25519.PublicKey)
}

func (self *testOutboxMember) key(sidecarId sidecar.Id) ed25519.PublicKey {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.devices[sidecarId]
}

// One prover host of the member, on the world's MX world and edge, its own pins and keys, the member's mailbox.
type testOutboxHost struct {
	device *testOutboxDevice
	prover *sidecartest.FakeSmtpProver
	host   *sidecar.SmtpProverHost
	sender *sidecar.SmtpSender
	runner *sidecar.SmtpOutboxRunner
}

// A host whose prover's DATA cap is dataProofByteCount, admitted to member, its p/ written by one idle step.
func (self *testSenderWorld) addHost(member *testOutboxMember, dataProofByteCount uint64, hold *sidecar.SmtpStatusHold) *testOutboxHost {
	self.t.Helper()
	device := newTestOutboxDevice()
	member.admit(device)
	proverSettings := sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.DataProofByteCount = dataProofByteCount
	proverSettings.Measure = &sidecar.SmtpProverMeasure{
		DataProofBytes: dataProofByteCount, DataBytesPerSecond: 512, MeasureTime: self.tls.clock.Now(), UnitTime: 5 * time.Second,
		HeadByteCount: 831, HeaderRecordByteCount: 1199, EnvelopeGroupCount: 13,
	}
	prover := sidecartest.NewFakeSmtpProver(proverSettings)
	host, err := sidecar.NewSmtpProverHost(&sidecar.SmtpProverHostArgs{
		Prover: prover, Mailbox: self.mailbox, SidecarId: device.sidecarId, MailEnabled: func() bool { return true },
		Settings: self.settings, Clock: self.tls.clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if err := host.Idle(context.Background()); err != nil {
		self.t.Fatal(err)
	}
	store := sidecartest.NewFakeStore()
	pins := sidecar.NewSmtpPinStore(store.Root(), self.settings, self.tls.clock, nil)
	policy := sidecar.NewSmtpTlsPolicy(
		sidecar.NewSmtpDane(self.tls.anchors, self.tls.clock, nil),
		sidecar.NewSmtpMtaSts(self.tls.zone, self.tls.world.MtaStsTransport(), store.Root(), self.settings, self.tls.clock),
		pins, sidecar.NewSmtpTlsAllowanceStore(store.Root(), self.settings, self.tls.clock), self.tls.gate, self.tls.zone, self.tls.pki.roots,
		self.settings, self.tls.clock)
	sender, err := sidecar.NewSmtpSender(&sidecar.SmtpSenderArgs{
		Dialer: self.stub, Prover: prover, Policy: policy, Pins: pins,
		Dkim:         sidecar.NewSmtpDkimKeys(newTestMemorySecrets(), testEchoDkimPublisher{}, self.settings, self.tls.clock, nil),
		Mailbox:      self.mailbox,
		MemberDevice: func(sidecarId sidecar.Id) bool { return member.key(sidecarId) != nil },
		Measure:      host.Measure, ReadyKeySets: host.ReadyKeySets, SendHold: host.HoldForSend,
		Settings: self.settings, Clock: self.tls.clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(sender.Close)
	runner, err := sidecar.NewSmtpOutboxRunner(&sidecar.SmtpOutboxRunnerArgs{
		Sender: sender, Mailbox: self.mailbox, SidecarId: device.sidecarId, MemberDeviceKey: member.key,
		Consented: func() bool { return true }, Hold: hold, OwnCap: host.Cap, Settings: self.settings, Clock: self.tls.clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return &testOutboxHost{device: device, prover: prover, host: host, sender: sender, runner: runner}
}

// The host the rendezvous hash picks among sidecarIds, as the runner computes it.
func testRendezvousPick(effectKey []byte, sidecarIds ...sidecar.Id) sidecar.Id {
	var picked sidecar.Id
	var pickedScore []byte
	for _, sidecarId := range sidecarIds {
		score := sha256.Sum256(append(bytes.Clone(effectKey), sidecarId.Bytes()...))
		if pickedScore == nil || 0 < bytes.Compare(score[:], pickedScore) {
			picked, pickedScore = sidecarId, score[:]
		}
	}
	return picked
}

// Queues message at o/ as its composing device writes it, signed by device.
func (self *testSenderWorld) queue(device *testOutboxDevice, message *sidecar.SmtpOutboundMessage) {
	self.t.Helper()
	signed, err := sidecar.SignSmtpOutboxEntry(message, device.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	if !self.mailbox.PutOutbox(message.EffectKey, signed, message.Message) {
		self.t.Fatal("o/ held the entry already")
	}
}

func (self *testSenderWorld) runOnce(host *testOutboxHost) *sidecar.SmtpOutboxPass {
	self.t.Helper()
	pass, err := host.runner.RunOnce(context.Background())
	if err != nil {
		self.t.Fatal(err)
	}
	return pass
}

// FS-123's phone half: queued from a phone, the host the hash picks is under the cap and leaves the DATA domain as
// deferred, and a second host whose recorded cap fits sends it; the phone reads the outcome from or/, and its Check
// prices the send on the member's p/ records.
func TestSmtpOutboxFs123PhoneHalf(t *testing.T) {
	member := &testOutboxMember{devices: map[sidecar.Id]ed25519.PublicKey{}}
	world := newTestSenderWorld(t, &testSenderOptions{noProver: true, memberDevice: func(sidecarId sidecar.Id) bool { return member.key(sidecarId) != nil }})
	dataMx := world.addDomain(testDataDomain, testDataHost, testDataAddress, testDataOnlyScript())
	phone := newTestOutboxDevice()
	member.admit(phone)
	small := world.addHost(member, 2*1024, nil)
	large := world.addHost(member, 1024*1024, nil)

	// an effect key the hash gives the small host
	body := strings.Repeat("A line of the body, long enough to pass a small cap.\r\n", 60)
	var message *sidecar.SmtpOutboundMessage
	for {
		message = world.message([]string{"dave@" + testDataDomain}, nil, body)
		if testRendezvousPick(message.EffectKey, small.device.sidecarId, large.device.sidecarId) == small.device.sidecarId {
			break
		}
	}
	// the phone's own sender only queues, and its Check reads the member's p/ records
	if result := world.send(message); testDomainOutcome(t, result, testDataDomain).Outcome != sidecar.SmtpOutcomeQueued {
		t.Fatalf("the phone: %+v", result.Domains)
	}
	phoneSender := world.sender
	world.queue(phone, message)

	if pass := world.runOnce(large); pass.Sent != 0 || pass.Left != 1 {
		t.Errorf("the host the hash did not pick: %+v", pass)
	}
	if pass := world.runOnce(small); pass.Sent != 1 {
		t.Fatalf("the picked host: %+v", pass)
	}
	outcomes, err := world.mailbox.ReadOutcomes(context.Background(), message.EffectKey)
	if err != nil || len(outcomes) != 1 || outcomes[0].Outcome != sidecar.SmtpOutcomeDeferred || outcomes[0].ByteCount <= 2*1024 {
		t.Fatalf("after the small host: %+v, %v", outcomes, err)
	}
	if len(dataMx.Transactions()) != 0 {
		t.Fatal("a host under the cap reached MAIL")
	}
	// the small host leaves it from here; the large one takes it
	if pass := world.runOnce(small); pass.Sent != 0 {
		t.Errorf("the small host took it again: %+v", pass)
	}
	if pass := world.runOnce(large); pass.Sent != 1 {
		t.Fatalf("the large host: %+v", pass)
	}
	if transactions := dataMx.Transactions(); len(transactions) != 1 || transactions[0].Mode != sidecar.SmtpModeData {
		t.Fatalf("transactions %+v", transactions)
	}
	// the composing device reads the sending host's outcome
	outcomes, err = world.mailbox.ReadOutcomes(context.Background(), message.EffectKey)
	if err != nil || len(outcomes) != 1 || outcomes[0].Outcome != sidecar.SmtpOutcomeSent || outcomes[0].TlsLevel != sidecar.SmtpTlsLevelIndependentMx {
		t.Errorf("or/ for the phone: %+v, %v", outcomes, err)
	}
	// the entry goes once sent and past its window, which an entry with no approval has none of
	if pass := world.runOnce(large); pass.Removed != 1 {
		t.Errorf("not removed: %+v", pass)
	}
	if effectKeys, _ := world.mailbox.ListOutbox(context.Background()); len(effectKeys) != 0 {
		t.Errorf("o/ still holds %d entries", len(effectKeys))
	}

	// the phone's check: the member's largest cap, and the DATA mode or/ now names
	check, err := phoneSender.Check(context.Background(), world.message([]string{"dave@" + testDataDomain}, nil, body))
	if err != nil {
		t.Fatal(err)
	}
	if domain := check.Domains[0]; domain.CapByteCount != 1024*1024 || domain.Mode != sidecar.SmtpModeData || domain.Prediction != sidecar.SmtpCheckOk || domain.ExpectedDelay <= 0 {
		t.Errorf("the phone's check %+v", domain)
	}
}

// An entry signed by a key no device of the member holds, or whose message is not the one it names, is refused and
// never sent.
func TestSmtpOutboxRefusesAForgedEntry(t *testing.T) {
	world := newTestSenderWorld(t, &testSenderOptions{noProver: true})
	member := &testOutboxMember{devices: map[sidecar.Id]ed25519.PublicKey{}}
	host := world.addHost(member, 1024*1024, nil)
	stranger := newTestOutboxDevice()
	world.queue(stranger, world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))

	phone := newTestOutboxDevice()
	member.admit(phone)
	tampered := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	signed, err := sidecar.SignSmtpOutboxEntry(tampered, phone.sign)
	if err != nil {
		t.Fatal(err)
	}
	world.mailbox.PutOutbox(tampered.EffectKey, signed, []byte(strings.Replace(string(tampered.Message), "body", "evil", 1)))

	pass := world.runOnce(host)
	if pass.Refused != 2 || pass.Sent != 0 || len(world.mx.Transactions()) != 0 || len(host.prover.Sends()) != 0 {
		t.Errorf("pass %+v, %d transactions", pass, len(world.mx.Transactions()))
	}
}

// A SmtpStatus HALTED hint holds the queue until its retry_after_ms; then it sends.
func TestSmtpOutboxHaltedQueueHoldsAndResumes(t *testing.T) {
	world := newTestSenderWorld(t, &testSenderOptions{noProver: true})
	member := &testOutboxMember{devices: map[sidecar.Id]ed25519.PublicKey{}}
	hold := sidecar.NewSmtpStatusHold(world.settings, world.tls.clock)
	host := world.addHost(member, 1024*1024, hold)
	phone := newTestOutboxDevice()
	member.admit(phone)
	world.queue(phone, world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))

	hint, err := proto.Marshal(&protocol.SmtpStatus{Kind: uint32(protocol.SmtpStatusKind_SMTP_STATUS_HALTED), RetryAfterMs: 60_000})
	if err != nil {
		t.Fatal(err)
	}
	hold.Notice(sidecar.PushNotice{Topic: sidecar.PushTopicMail, Kind: uint32(protocol.MessageType_SMTP_STATUS), Hint: hint})
	if pass := world.runOnce(host); !pass.Held || pass.Sent != 0 {
		t.Errorf("a halted queue: %+v", pass)
	}
	world.tls.clock.Advance(59 * time.Second)
	if pass := world.runOnce(host); !pass.Held {
		t.Errorf("a halt ended early: %+v", pass)
	}
	world.tls.clock.Advance(time.Second)
	if pass := world.runOnce(host); pass.Held || pass.Sent != 1 || len(world.mx.Transactions()) != 1 {
		t.Errorf("after the halt: %+v", pass)
	}
}

// Two hosts racing on one entry, neither yet in p/ so each takes it: at most two sends, and or/ keeps one outcome.
func TestSmtpOutboxTwoHostsRacingSendAtMostTwice(t *testing.T) {
	world := newTestSenderWorld(t, &testSenderOptions{noProver: true})
	member := &testOutboxMember{devices: map[sidecar.Id]ed25519.PublicKey{}}
	first := world.addHost(member, 1024*1024, nil)
	second := world.addHost(member, 1024*1024, nil)
	phone := newTestOutboxDevice()
	member.admit(phone)
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	world.queue(phone, message)
	// neither host's p/ counts as a member device's any more, so the hash picks no one and both take the entry
	member.stateLock.Lock()
	delete(member.devices, first.device.sidecarId)
	delete(member.devices, second.device.sidecarId)
	member.stateLock.Unlock()

	var group sync.WaitGroup
	for _, host := range []*testOutboxHost{first, second} {
		group.Add(1)
		go func() {
			defer group.Done()
			host.runner.RunOnce(context.Background())
		}()
	}
	group.Wait()
	transactionCount := len(world.mx.Transactions())
	if transactionCount < 1 || 2 < transactionCount {
		t.Errorf("%d transactions", transactionCount)
	}
	outcomes, err := world.mailbox.ReadOutcomes(context.Background(), message.EffectKey)
	if err != nil || len(outcomes) != 1 || (outcomes[0].Outcome != sidecar.SmtpOutcomeSent && outcomes[0].Outcome != sidecar.SmtpOutcomeQueued) {
		t.Errorf("or/ %+v, %v", outcomes, err)
	}
}

// An entry with an approval stays in o/ after it is sent until the approval's not_after has passed.
func TestSmtpOutboxKeepsAnEntryThroughItsApprovalWindow(t *testing.T) {
	world := newTestSenderWorld(t, &testSenderOptions{noProver: true})
	member := &testOutboxMember{devices: map[sidecar.Id]ed25519.PublicKey{}}
	host := world.addHost(member, 1024*1024, nil)
	phone := newTestOutboxDevice()
	member.admit(phone)
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	message.ApprovalNotAfter = world.tls.clock.Now().Add(time.Hour)
	world.queue(phone, message)
	if pass := world.runOnce(host); pass.Sent != 1 {
		t.Fatalf("pass %+v", pass)
	}
	if pass := world.runOnce(host); pass.Removed != 0 || pass.Sent != 0 {
		t.Errorf("inside the window: %+v", pass)
	}
	world.tls.clock.Advance(time.Hour)
	if pass := world.runOnce(host); pass.Removed != 1 {
		t.Errorf("past the window: %+v", pass)
	}
	if len(world.mx.Transactions()) != 1 {
		t.Errorf("%d transactions", len(world.mx.Transactions()))
	}
}

// A host that is no consented device of the member, such as an agent sidecar holding a wrap, takes nothing.
func TestSmtpOutboxUnconsentedHostTakesNothing(t *testing.T) {
	world := newTestSenderWorld(t, &testSenderOptions{noProver: true})
	member := &testOutboxMember{devices: map[sidecar.Id]ed25519.PublicKey{}}
	host := world.addHost(member, 1024*1024, nil)
	phone := newTestOutboxDevice()
	member.admit(phone)
	world.queue(phone, world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))
	runner, err := sidecar.NewSmtpOutboxRunner(&sidecar.SmtpOutboxRunnerArgs{
		Sender: host.sender, Mailbox: world.mailbox, SidecarId: host.device.sidecarId, MemberDeviceKey: member.key,
		Consented: func() bool { return false }, Settings: world.settings, Clock: world.tls.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pass, err := runner.RunOnce(context.Background()); err != nil || pass.Sent != 0 || world.mailbox.OpCount("ListOutbox") != 0 {
		t.Errorf("pass %+v, %v", pass, err)
	}
}
