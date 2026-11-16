//go:build !sidecar_http && !js && !ios_extension

// FS-23's mailbox case end to end on T2 (KEYS-M7-01; D-KEYS-17, D-MAIL-5, §15.5's reply row, §15.7's deposit row;
// owner decision 357): gkmschedule's mailbox world keyed on the real subset, and its receiver's SMTP session as
// MailSessionServer serves a direct MX's, depositing through MailDepositor and EvsRepo.Deposit into evsservice's
// engine on the world's fake host, its receiver's own group client deciding which drop key a deposit seals to. The
// receiver answers 250 only once a deposit sealed to a covered drop key is durable, and 451 4.3.0, never 250, while
// it holds none:
//
//   - with the readers online a message is deposited, 250, and a consented device ingests it, a deposit of the
//     receiver's naming the mailbox's recipient, and consumes it; every evs read refuses the receiver's token;
//   - with both readers offline past the drop key's life, the receiver's deposit asks gkm again each DropKeyWait, up
//     to DropKeyWaitCount times, and the session answers 451 4.3.0 with nothing reaching evs; a writer back with
//     nothing to ingest renews the key at its resync, and the sender's retry is deposited at the renewal, 250, which
//     the other reader, back too, ingests: one deposit, the retry's;
//   - with evs's gate off, on a sidecar_testhooks build, after a consented device's revocation the receiver answers
//     451 until a writer's REMOVE rotation covers it, though evs takes a deposit sealed to the stale key from a
//     depositor that skips the rule (fs_keys_mailbox_testhooks_test.go).
//
// The receiver's waits answer at once and its session's timers never fire, so nothing waits on real time.

package sidecartest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

// The mailbox's address and the sender's, synthetic (connect/CODESTYLE.md's test data rule).
const (
	fsKeysMailboxAddress = "owner@lbl0000001.root.example"
	fsKeysMailboxSender  = "sender@sender.example"
	fsKeysMailboxHost    = "mx.lbl0000001.root.example"
)

// MAIL-FORMAT.md's version of the MailIngress a direct listener builds.
const fsKeysMailboxIngressVersion = 1

// How many times the receiver's deposit asks again for a drop key it may seal to, each after an instant wait.
const fsKeysMailboxDropKeyWaitCount = 3

// evs's view of the mailbox world: its log's tip, the readers and writers it names there and the receiver, which may
// deposit and nothing else.
type fsKeysMailboxEvsAuth struct {
	keys       *gkmschedule.FsKeysWorld
	receiverId sidecar.Id
}

func (self *fsKeysMailboxEvsAuth) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *fsKeysMailboxEvsAuth) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	row := self.keys.Log.Tip().SidecarRow(sidecar.Id(*principal.SidecarId))
	if row == nil || row.GetRevokedAt() != 0 {
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *fsKeysMailboxEvsAuth) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	tip := self.keys.Log.Tip()
	sidecarId := sidecar.Id(*principal.SidecarId)
	reads := slices.Contains(tip.RepoReadersAt(repoId, now), sidecarId)
	writes := slices.Contains(tip.RepoWriters(repoId), sidecarId)
	switch {
	case repoId != self.keys.RepoId:
		return evsservice.EvsAuthDenied
	case rights&sidecar.AclEvsRead != 0 && !reads, rights&sidecar.AclEvsWrite != 0 && !writes, rights&sidecar.AclEvsAdmin != 0:
		return evsservice.EvsAuthDenied
	case rights&sidecar.AclEvsDeposit != 0 && !reads && sidecarId != self.receiverId:
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *fsKeysMailboxEvsAuth) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	if repoId != self.keys.RepoId {
		return nil, evsservice.EvsAuthDenied
	}
	return &evsservice.EvsRepoFacts{
		Kind: protocol.RepoKind_REPO_KIND_MAILBOX, OwnerMemberId: self.keys.MemberId, NetworkId: sidecar.Id(self.keys.NetworkId),
	}, evsservice.EvsAuthAllowed
}

// evs's push gate's view: the log's tip, as the gate cache would hold it.
type fsKeysMailboxGateViews struct {
	keys *gkmschedule.FsKeysWorld
}

func (self *fsKeysMailboxGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if networkId != sidecar.Id(self.keys.NetworkId) {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.keys.Log.Tip(), evsservice.EvsAuthAllowed
}

// The devices' transport to evs's engine, each push's step 8 waited out before its answer goes back.
type fsKeysMailboxEvsTransport struct {
	ctx    context.Context
	engine *evsservice.EvsEngine
}

func (self *fsKeysMailboxEvsTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	if strings.HasSuffix(request.URL.Path, "/push") {
		for {
			started, finished, changed := self.engine.StepEights()
			if started == finished {
				break
			}
			select {
			case <-changed:
			case <-self.ctx.Done():
				return nil, self.ctx.Err()
			}
		}
	}
	return recorder.Result(), nil
}

// The receiver's clock: the world's, whose waits answer at once, each counted, so a deposit's asks for a newer drop
// key run on without parking the test on the fake clock.
type fsKeysMailboxReceiverClock struct {
	clock *sidecartest.FakeClock

	stateLock sync.Mutex
	waitCount int
}

func (self *fsKeysMailboxReceiverClock) Now() time.Time {
	return self.clock.Now()
}

func (self *fsKeysMailboxReceiverClock) After(timeout time.Duration) <-chan time.Time {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.waitCount += 1
	}()
	fired := make(chan time.Time, 1)
	fired <- self.clock.Now()
	return fired
}

func (self *fsKeysMailboxReceiverClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return self.clock.AfterFunc(timeout, function)
}

// How many waits the receiver's clock has answered.
func (self *fsKeysMailboxReceiverClock) waits() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.waitCount
}

// The mailbox world with evs and the receiver's session on it.
type fsKeysMailboxSessionWorld struct {
	t        *testing.T
	ctx      context.Context
	keys     *gkmschedule.FsKeysWorld
	a        *gkmschedule.FsKeysDevice
	b        *gkmschedule.FsKeysDevice
	receiver *gkmschedule.FsKeysDevice
	engine   *evsservice.EvsEngine
	// the receiver's evs client, and its clock
	receiverEvs   *sidecar.EvsClient
	receiverClock *fsKeysMailboxReceiverClock
	session       *sidecar.MailSessionServer
	serverTls     *tls.Config
}

// gkmschedule's mailbox world on T2, evs's engine on its host, and the receiver's session over its depositor.
func newFsKeysMailboxSessionWorld(t *testing.T) *fsKeysMailboxSessionWorld {
	t.Helper()
	ctx := t.Context()
	keys, a, b, receiver := gkmschedule.NewFsKeysMailboxWorld(t, gkmschedule.FsKeysT2(t))
	host := keys.Host
	sidecartest.RegisterEvsTwins(host.Redis)
	host.Gates.OpenService(sidecar.ServiceGateEvs, keys.NetworkId)
	host.Quota.SetBalance(keys.NetworkId, 1024*1024*1024*1024)
	usage, err := evsservice.NewUsageBatcher(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	quota, err := evsservice.NewQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Close)
	receiptKey := sha256.Sum256([]byte("fs keys mailbox receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey[:], IssueFrom: keys.Clock.Now().Add(-48 * time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := evsservice.DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	settings.RepoCacheTtl = 0
	engine, err := evsservice.NewEvsEngine(ctx, host.ServiceHost(), settings, &evsservice.EvsEngineDeps{
		AuthState: &fsKeysMailboxEvsAuth{keys: keys, receiverId: receiver.SidecarId()},
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: &fsKeysMailboxGateViews{keys: keys},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	world := &fsKeysMailboxSessionWorld{
		t: t, ctx: ctx, keys: keys, a: a, b: b, receiver: receiver, engine: engine,
		receiverClock: &fsKeysMailboxReceiverClock{clock: keys.Clock},
	}
	world.receiverEvs = world.evsClient(receiver, receiver.Client, world.receiverClock)
	depositor, err := sidecar.NewMailDepositor(&sidecar.MailDepositorArgs{Repo: world.receiverEvs.Repo, ReceiverSidecarId: receiver.SidecarId()})
	if err != nil {
		t.Fatal(err)
	}
	world.session, err = sidecar.NewMailSessionServer(&sidecar.MailSessionArgs{
		ReceiverSidecarId: receiver.SidecarId(),
		Resolve: func(ctx context.Context, address string) (*sidecar.MailSessionRecipient, error) {
			if strings.ToLower(address) != fsKeysMailboxAddress {
				return &sidecar.MailSessionRecipient{}, nil
			}
			return &sidecar.MailSessionRecipient{Known: true, Address: fsKeysMailboxAddress, RepoId: keys.RepoId}, nil
		},
		Limits: func(ctx context.Context) (*sidecar.QuotaLimits, error) {
			return &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{
				"mail_inbound_message_bytes": 50 * 1024 * 1024, "mail_inbound_recipients": 100, "mail_inbound_repos_per_message": 8,
			}}, nil
		},
		Depositor:  depositor,
		SpoolStore: sidecartest.NewFakeStore().Root(),
		// a clock of the session's own, which never moves, so no session timer fires while the world's clock runs on
		Clock: sidecartest.NewFakeClock(keys.Clock.Now()),
	})
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(23),
		Subject:      pkix.Name{CommonName: fsKeysMailboxHost},
		DNSNames:     []string{fsKeysMailboxHost},
		NotBefore:    keys.Clock.Now().Add(-time.Hour),
		NotAfter:     keys.Clock.Now().Add(365 * 24 * time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	world.serverTls = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}},
		MinVersion:   tls.VersionTLS13,
	}
	return world
}

// An evs client of device over gkm, its tokens holding the scopes it asks for, or deposit alone for the receiver, as
// the exchange mints a deposit-only sidecar's.
func (self *fsKeysMailboxSessionWorld) evsClient(device *gkmschedule.FsKeysDevice, gkm sidecar.GkmClient, clock sidecar.Clock) *sidecar.EvsClient {
	self.t.Helper()
	keys := self.keys
	signer := device.Signer()
	connectSidecarId := connect.Id(signer.SidecarId)
	identity := &sidecar.SidecarIdentity{
		NetworkId: sidecar.Id(keys.NetworkId), SidecarId: signer.SidecarId, ClientId: sidecar.Id(device.ClientId), Generation: 1,
		IdentityPublicKey: signer.PublicKey(),
	}
	settings := sidecar.DefaultEvsSettings()
	settings.DropKeyWaitCount = fsKeysMailboxDropKeyWaitCount
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: sidecar.Id(keys.NetworkId),
		EvsUrl:    "https://evs.example",
		Transport: &fsKeysMailboxEvsTransport{ctx: self.ctx, engine: self.engine},
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			if device == self.receiver {
				scopes = []string{"repo:" + keys.RepoId.String() + ":deposit"}
			}
			return keys.Host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: keys.NetworkId, ClientId: device.ClientId, SidecarId: &connectSidecarId, Audience: evsservice.EvsAudience,
				Scopes: scopes, IssuedAt: keys.Clock.Now(), ExpiresAt: keys.Clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkm,
		Store:    sidecartest.NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return keys.Log.Tip() },
		Clock:    clock,
		Log:      sidecar.NewNoopLogger(),
		Settings: settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client
}

// A message as a sender writes it.
func fsKeysMailboxMessage(subject string) []byte {
	return []byte("From: <" + fsKeysMailboxSender + ">\r\nTo: <" + fsKeysMailboxAddress + ">\r\nSubject: " + subject +
		"\r\nMessage-ID: <" + subject + "@sender.example>\r\n\r\nA message for FS-23's mailbox case.\r\n")
}

// One sender's transaction with the receiver over a fresh direct-MX connection, through DATA: the reply to the
// message.
func (self *fsKeysMailboxSessionWorld) send(message []byte) *sidecartest.MailReply {
	self.t.Helper()
	serverEnd, senderEnd := net.Pipe()
	served := make(chan struct{})
	go func() {
		defer close(served)
		tlsConn := tls.Server(serverEnd, self.serverTls)
		if err := tlsConn.HandshakeContext(self.ctx); err != nil {
			tlsConn.Close()
			return
		}
		ingress := &protocol.MailIngress{
			Version: fsKeysMailboxIngressVersion, SenderIp: []byte{192, 0, 2, 25}, SenderPort: 40000, Sni: fsKeysMailboxHost,
			EhloName: "mail.sender.example", ReceiveTimeMillis: uint64(self.keys.Clock.Now().UnixMilli()),
		}
		self.session.ServeDirect(self.ctx, tlsConn, sha256.Sum256(nil), ingress)
	}()
	defer func() {
		senderEnd.Close()
		<-served
	}()
	conn := tls.Client(senderEnd, sidecartest.MailMtaTlsConfig(fsKeysMailboxHost, tls.VersionTLS13))
	if err := conn.HandshakeContext(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	mta := sidecartest.NewScriptedMta(conn)
	for _, step := range []func() (*sidecartest.MailReply, error){
		func() (*sidecartest.MailReply, error) { return mta.Ehlo("mail.sender.example") },
		func() (*sidecartest.MailReply, error) { return mta.MailFrom(fsKeysMailboxSender) },
		func() (*sidecartest.MailReply, error) { return mta.RcptTo(fsKeysMailboxAddress) },
	} {
		reply, err := step()
		if err != nil || !reply.Is(250) {
			self.t.Fatalf("the transaction before DATA: %s %v", reply, err)
		}
	}
	reply, err := mta.Data(message)
	if err != nil {
		self.t.Fatalf("DATA: %v", err)
	}
	mta.Quit()
	return reply
}

// What a reader takes of one deposit: the deposit as evs holds it, the message, and the trailer that names who
// deposited it for whom.
type fsKeysMailboxIngested struct {
	deposit *sidecar.EvsDeposit
	message []byte
	trailer *protocol.MailDeposit
}

// The receiver's deposits device reads past what it consumed, each split as ingest splits it (MAIL-FORMAT.md: the
// message, its MailDeposit, u32be of that encoding's length); then a CONSUME of them all.
func (self *fsKeysMailboxSessionWorld) ingest(device *gkmschedule.FsKeysDevice, evs *sidecar.EvsClient) []*fsKeysMailboxIngested {
	self.t.Helper()
	ingested := []*fsKeysMailboxIngested{}
	repo := evs.Repo(self.keys.RepoId)
	err := repo.ReadDeposits(self.ctx, self.receiver.SidecarId(), 0, func(deposit *sidecar.EvsDeposit, body io.Reader) error {
		plaintext, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		if len(plaintext) < 4 {
			return errors.New("a deposit too short to hold its trailer")
		}
		trailerByteCount := int(binary.BigEndian.Uint32(plaintext[len(plaintext)-4:]))
		if len(plaintext)-4 < trailerByteCount {
			return errors.New("a deposit's trailer past its body")
		}
		trailer := &protocol.MailDeposit{}
		if err := proto.Unmarshal(plaintext[len(plaintext)-4-trailerByteCount:len(plaintext)-4], trailer); err != nil {
			return err
		}
		ingested = append(ingested, &fsKeysMailboxIngested{
			deposit: deposit, message: plaintext[:len(plaintext)-4-trailerByteCount], trailer: trailer,
		})
		return nil
	})
	if err != nil {
		self.t.Fatalf("%s's ingest: %v", device.Label, err)
	}
	if len(ingested) == 0 {
		return ingested
	}
	entryIds := []sidecar.EvsToken{}
	for _, taken := range ingested {
		entryIds = append(entryIds, taken.deposit.EntryId)
		if !bytes.Equal(taken.trailer.GetReceiverSidecarId(), self.receiver.SidecarId().Bytes()) || taken.deposit.SignerSidecarId != self.receiver.SidecarId() ||
			!slices.Equal(taken.trailer.GetRecipients(), []string{fsKeysMailboxAddress}) {
			self.t.Errorf("a deposit not the receiver's for the mailbox")
		}
	}
	consumed := ingested[len(ingested)-1].deposit.Version
	if _, err := repo.Consume(self.ctx, &sidecar.EvsConsumeArgs{
		DepositRefId: sidecar.EvsDepositRefId(self.keys.RepoId, self.receiver.SidecarId()), EntryIds: entryIds, ConsumedThrough: consumed,
	}); err != nil {
		self.t.Fatalf("%s's CONSUME: %v", device.Label, err)
	}
	return ingested
}

// Whether reply is 451 4.3.0.
func fsKeysMailboxTryLater(reply *sidecartest.MailReply) bool {
	return reply.Is(451) && 0 < len(reply.Lines) && strings.HasPrefix(reply.Lines[0], "4.3.0")
}

// FS-23's mailbox case through the receiver's session: 250 for a deposit at a covered drop key, ingested by a
// consented device; 451 4.3.0, never 250, once both readers are offline past the key's life, with nothing reaching
// evs; a writer back with nothing to ingest renews it, and the sender's retry is deposited at the renewal and ingested
// by the other reader, back too.
func TestFsKeysMailboxTheReceiverAnswers451WithoutACoveredDropKey(t *testing.T) {
	world := newFsKeysMailboxSessionWorld(t)
	keys := world.keys
	aEvs := world.evsClient(world.a, world.a.Client, keys.Clock)
	first := fsKeysMailboxMessage("first")
	if reply := world.send(first); !reply.Is(250) {
		t.Fatalf("a message at a covered drop key: %s", reply)
	}
	ingested := world.ingest(world.a, aEvs)
	if len(ingested) != 1 || !bytes.Equal(ingested[0].message, first) {
		t.Fatalf("a's ingest: %d deposits", len(ingested))
	}
	// every evs read route refuses the receiver's deposit-only token at its guard, on its own deposit ref too
	world.refusesReceiverReads()

	// both readers offline past the drop key's life: the receiver asks again each wait, then 451, and nothing is
	// deposited
	notAfter := time.UnixMilli(keys.Generation(1).Rotate.GetDropNotAfterMs())
	world.a.Offline = true
	world.b.Offline = true
	keys.Clock.AdvanceTo(notAfter.Add(time.Hour))
	second := fsKeysMailboxMessage("second")
	waits := world.receiverClock.waits()
	if reply := world.send(second); !fsKeysMailboxTryLater(reply) {
		t.Fatalf("a message with no covered drop key: %s", reply)
	}
	if asked := world.receiverClock.waits() - waits; asked != fsKeysMailboxDropKeyWaitCount {
		t.Errorf("the receiver waited %d times for a newer drop key, not %d", asked, fsKeysMailboxDropKeyWaitCount)
	}
	if reply := world.send(second); !fsKeysMailboxTryLater(reply) {
		t.Fatalf("the sender's first retry: %s", reply)
	}

	// a, back with nothing to ingest, renews at its resync; the sender's next retry is deposited at the renewal
	keys.BackOnline(world.a)
	if keys.GenerationCount() != 2 || sidecar.GkmCause(keys.Generation(2).Rotate.GetCause()) != sidecar.GkmCauseSchedule {
		t.Fatalf("a's resync did not renew the drop key: %d generations", keys.GenerationCount())
	}
	if reply := world.send(second); !reply.Is(250) {
		t.Fatalf("the retry at the renewed drop key: %s", reply)
	}
	keys.BackOnline(world.b)
	bEvs := world.evsClient(world.b, world.b.Client, keys.Clock)
	ingested = world.ingest(world.b, bEvs)
	if len(ingested) != 1 || !bytes.Equal(ingested[0].message, second) {
		t.Fatalf("b's ingest after the renewal: %d deposits", len(ingested))
	}
	if len(world.receiver.Alarms) != 0 {
		t.Errorf("the receiver alarmed: %+v", world.receiver.Alarms[0])
	}
}

// evs's read, refs and log routes each answer the receiver's deposit-only token 403 at their guard, its own deposit
// ref named or not: a deposit scope reads nothing (FS-23).
func (self *fsKeysMailboxSessionWorld) refusesReceiverReads() {
	self.t.Helper()
	keys := self.keys
	depositRefId := sidecar.EvsDepositRefId(keys.RepoId, self.receiver.SidecarId())
	readRequest, err := proto.Marshal(&protocol.EvsReadRequest{RefId: depositRefId.Bytes(), Fresh: true})
	if err != nil {
		self.t.Fatal(err)
	}
	connectSidecarId := connect.Id(self.receiver.SidecarId())
	token := keys.Host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: keys.NetworkId, ClientId: self.receiver.ClientId, SidecarId: &connectSidecarId, Audience: evsservice.EvsAudience,
		Scopes: []string{"repo:" + keys.RepoId.String() + ":deposit"}, IssuedAt: keys.Clock.Now(), ExpiresAt: keys.Clock.Now().Add(15 * time.Minute),
	})
	for _, route := range []struct {
		method string
		path   string
		body   []byte
	}{
		{method: http.MethodPost, path: "/read", body: readRequest},
		{method: http.MethodGet, path: "/refs"},
		{method: http.MethodGet, path: "/log?ref=" + sidecar.EvsKeyId(depositRefId) + "&since=1"},
	} {
		request := httptest.NewRequestWithContext(self.ctx, route.method, "https://evs.example/evs/v1/repos/"+sidecar.EvsKeyId(keys.RepoId)+route.path, bytes.NewReader(route.body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/octet-stream")
		recorder := httptest.NewRecorder()
		self.engine.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			self.t.Errorf("%s %s under the receiver's deposit scope: %d", route.method, route.path, recorder.Code)
		}
	}
}
