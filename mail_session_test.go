//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-14's session through the receiver (MAIL-M7-13) on its fakes, over the in-memory stream seam and a fake
// clock, with a sender speaking SMTP after the handshake: 250 only once every deposit is durable, held at evs, and
// 451 4.3.0, never a 5xx or 530, for a deposit that fails or a session that ends first; RCPT's refusals; EHLO's
// extensions; a repo's deposit naming its own recipients alone; no authentication result refusing mail; BDAT and
// RSET; a long line; MAIL's 60 s; and a stream that is not the router's.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The test's addresses, under the network's label.
const (
	testMailSessionAlice = "alice@lbl0000001.root.example"
	testMailSessionBob   = "bob@lbl0000001.root.example"
	testMailSessionCarol = "carol@lbl0000001.root.example"
)

// One deposit a fake repo took: its plaintext's hash and size, and its message and trailer split as ingest splits
// them, the message kept only while it is small.
type mailSessionTestDeposit struct {
	repoId        Id
	size          int64
	sha256        [sha256.Size]byte
	message       []byte
	messageSha256 [sha256.Size]byte
	trailer       *protocol.MailDeposit
}

// A repo's deposit route in memory.
type mailSessionTestRepo struct {
	world  *mailSessionTestWorld
	repoId Id
}

// The deposits of a message whose plaintext passes this many bytes keep only a tail, which holds the trailer.
const testMailSessionKeptByteCount = 1024 * 1024

// See mailDepositRightRepo.
func (self *mailSessionTestRepo) depositRight(depositorId Id) (bool, bool) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if self.world.refusedRepos[self.repoId] {
		return false, true
	}
	return false, false
}

func (self *mailSessionTestRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	world := self.world
	hash := sha256.New()
	head := &bytes.Buffer{}
	tail := []byte{}
	buffer := make([]byte, 64*1024)
	size := int64(0)
	for {
		byteCount, err := args.Body.Read(buffer)
		if 0 < byteCount {
			hash.Write(buffer[:byteCount])
			size += int64(byteCount)
			if head.Len() < testMailSessionKeptByteCount+64*1024 {
				head.Write(buffer[:byteCount])
			}
			tail = append(tail, buffer[:byteCount]...)
			if 128*1024 < len(tail) {
				tail = append([]byte(nil), tail[len(tail)-128*1024:]...)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if size != args.Size {
		world.t.Errorf("a deposit of %d bytes said %d", size, args.Size)
	}
	deposit := &mailSessionTestDeposit{repoId: self.repoId, size: size}
	copy(deposit.sha256[:], hash.Sum(nil))
	plaintext := tail
	if size <= int64(head.Len()) {
		plaintext = head.Bytes()
	}
	message, trailer, err := mailSplitDeposit(plaintext, DefaultMailIngestSettings().TrailerMaxByteCount)
	if err != nil {
		world.t.Errorf("a deposit that does not split: %v", err)
	} else {
		deposit.trailer = trailer
		if size <= int64(head.Len()) {
			deposit.message = bytes.Clone(message)
			deposit.messageSha256 = sha256.Sum256(message)
		}
	}
	world.depositCalls.Update(func(count int) int { return count + 1 })
	hold, depositErr := func() (chan struct{}, error) {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		return world.hold, world.depositErr
	}()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if depositErr != nil {
		return nil, depositErr
	}
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	world.deposits = append(world.deposits, deposit)
	return &EvsDepositResult{EntryId: NewEvsRandomToken(), Version: uint64(len(world.deposits))}, nil
}

// The session's world: the receiver's, the session server on it, mailcfg's answers, the network's status and limits,
// and the repos' deposits.
type mailSessionTestWorld struct {
	*mailReceiverTestWorld
	server *MailSessionServer

	stateLock  sync.Mutex
	recipients map[string]*MailSessionRecipient
	resolveErr error
	status     *MailNetworkStatus
	limits     map[string]int64
	limitsErr  error
	// the limits' enforced, false as an older api answers
	enforced bool
	deposits []*mailSessionTestDeposit
	// a deposit waits on it while set, as evs holding a push would
	hold       chan struct{}
	depositErr error
	// repos the receiver's own verified state gives no deposit (mailDepositRightRepo); every other repo's right is not
	// known, as a client holding no ACL state's is
	refusedRepos map[Id]bool
	// raised as each deposit reaches its repo, before its hold
	depositCalls *MonitorValue[int]
}

// A world whose session server takes mutate's changes to its args, serving once the receiver's key is live.
func newMailSessionTestWorld(t *testing.T, mutate func(args *MailSessionArgs)) *mailSessionTestWorld {
	t.Helper()
	world := &mailSessionTestWorld{
		mailReceiverTestWorld: newMailReceiverTestWorld(t, nil),
		recipients: map[string]*MailSessionRecipient{
			testMailSessionAlice: {Known: true, Address: testMailSessionAlice, RepoId: NewId()},
			testMailSessionBob:   {Known: true, Address: testMailSessionBob, RepoId: NewId()},
			testMailSessionCarol: {Known: true, Address: testMailSessionCarol, RepoId: NewId()},
		},
		status: &MailNetworkStatus{Enabled: true},
		limits: map[string]int64{
			mailLimitInboundMessageBytes:    50 * 1024 * 1024,
			mailLimitInboundRecipients:      100,
			mailLimitInboundReposPerMessage: 8,
		},
		depositCalls: NewMonitorValue(0),
	}
	depositor := newMailDepositor(func(repoId Id) mailDepositRepo {
		return &mailSessionTestRepo{world: world, repoId: repoId}
	}, &MailDepositorArgs{ReceiverSidecarId: testMailSessionReceiverId})
	args := &MailSessionArgs{
		ReceiverSidecarId: testMailSessionReceiverId,
		Resolve: func(ctx context.Context, address string) (*MailSessionRecipient, error) {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			if world.resolveErr != nil {
				return nil, world.resolveErr
			}
			recipient, ok := world.recipients[strings.ToLower(address)]
			if !ok {
				return &MailSessionRecipient{}, nil
			}
			copied := *recipient
			return &copied, nil
		},
		Status: func(ctx context.Context) (*MailNetworkStatus, error) {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			copied := *world.status
			return &copied, nil
		},
		Limits: func(ctx context.Context) (*QuotaLimits, error) {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			if world.limitsErr != nil {
				return nil, world.limitsErr
			}
			limits := &QuotaLimits{Tier: "pro", Limits: map[string]int64{}, Enforced: world.enforced}
			for key, value := range world.limits {
				limits.Limits[key] = value
			}
			return limits, nil
		},
		Depositor:  depositor,
		SpoolStore: world.store,
		Clock:      world.clock,
	}
	if mutate != nil {
		mutate(args)
	}
	server, err := NewMailSessionServer(args)
	if err != nil {
		t.Fatal(err)
	}
	world.server = server
	world.newReceiver(func(receiverArgs *MailReceiverArgs) {
		receiverArgs.Serve = server.Serve
	})
	world.startServing()
	return world
}

// The receiver every test deposit names.
var testMailSessionReceiverId = Id{0x6d, 0x61, 0x69, 0x6c}

// The router's MailIngress for a test stream.
func testMailSessionIngress(t *testing.T) []byte {
	t.Helper()
	metadata, err := proto.Marshal(&protocol.MailIngress{
		Version:           mailFormatVersion,
		SenderIp:          []byte{192, 0, 2, 25},
		SenderPort:        40000,
		Sni:               testMailReceiverServerName,
		EhloName:          "mail.sender.example",
		ReceiveTimeMillis: 1794312000000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

// A sender speaking SMTP over the stream, past the handshake.
type mailSessionTestSender struct {
	t    *testing.T
	conn *tls.Conn
	text *textproto.Conn
}

// A sender on a fresh stream from the edge, opened with metadata.
func (self *mailSessionTestWorld) open(metadata []byte) *mailSessionTestSender {
	self.t.Helper()
	return self.openNaming(metadata, testMailReceiverServerName)
}

// A sender on a fresh stream from the edge, opened with metadata, whose ClientHello names serverName as its SNI, or
// sends none when it is empty.
func (self *mailSessionTestWorld) openNaming(metadata []byte, serverName string) *mailSessionTestSender {
	self.t.Helper()
	listenerEnd, senderEnd := newSocketStreamPipe(1024 * 1024)
	ticket := &protocol.SocketTicket{DialerNetworkId: self.edgeNetworkId.Bytes(), Name: "smtp/25/mx"}
	self.listener.conns <- newSocketConn(listenerEnd, &SocketAddr{}, &SocketAddr{}, ticket, metadata)
	conn := tls.Client(newSocketConn(senderEnd, &SocketAddr{}, &SocketAddr{}, nil, nil), &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	if err := conn.HandshakeContext(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(func() { conn.Close() })
	return &mailSessionTestSender{t: self.t, conn: conn, text: textproto.NewConn(conn)}
}

// One reply: its code and its lines' text.
func (self *mailSessionTestSender) reply() (int, string) {
	self.t.Helper()
	code, message, err := self.text.ReadResponse(0)
	if err != nil {
		var protocolErr textproto.ProtocolError
		if !errors.As(err, &protocolErr) {
			return 0, err.Error()
		}
	}
	return code, message
}

// A command and its reply.
func (self *mailSessionTestSender) command(line string) (int, string) {
	self.t.Helper()
	if err := self.text.PrintfLine("%s", line); err != nil {
		return 0, err.Error()
	}
	return self.reply()
}

// A command whose reply must be code.
func (self *mailSessionTestSender) expect(line string, code int) string {
	self.t.Helper()
	got, message := self.command(line)
	if got != code {
		self.t.Fatalf("%q answered %d %s, not %d", line, got, message, code)
	}
	return message
}

// DATA's 354, the message dot-stuffed, and the reply to its end, which the sender reads only from replies.
func (self *mailSessionTestSender) data(message []byte) (chan int, chan string) {
	self.t.Helper()
	self.expect("DATA", 354)
	writer := self.text.DotWriter()
	if _, err := writer.Write(message); err != nil {
		self.t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		self.t.Fatal(err)
	}
	codes, messages := make(chan int, 1), make(chan string, 1)
	go func() {
		code, message := self.reply()
		codes <- code
		messages <- message
	}()
	return codes, messages
}

// EHLO, MAIL and an RCPT for each recipient, every one taken.
func (self *mailSessionTestSender) envelope(recipients ...string) {
	self.t.Helper()
	self.expect("EHLO mail.sender.example", 250)
	self.expect("MAIL FROM:<bounce@sender.example>", 250)
	for _, recipient := range recipients {
		self.expect("RCPT TO:<"+recipient+">", 250)
	}
}

// A small synthetic message.
func testMailSessionMessage(subject string) []byte {
	return []byte("From: Sender <sender@sender.example>\r\nTo: Alice <" + testMailSessionAlice + ">\r\nSubject: " + subject +
		"\r\nMessage-ID: <" + subject + "@sender.example>\r\n\r\nA synthetic body.\r\n")
}

// The deposits taken so far.
func (self *mailSessionTestWorld) takenDeposits() []*mailSessionTestDeposit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.deposits)
}

// Blocks until count deposits have reached their repos.
func (self *mailSessionTestWorld) awaitDepositCalls(count int) {
	for {
		calls, notify := self.depositCalls.Get()
		if count <= calls {
			return
		}
		<-notify
	}
}

// 250 only once evs confirmed the deposit: while evs holds it the sender has no reply, and its release brings 250,
// the message deposited as received, its trailer naming this receiver, its ingress and its recipients.
func TestMailSessionAnswers250OnlyOnceTheDepositIsDurable(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	hold := make(chan struct{})
	world.hold = hold
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice)
	message := testMailSessionMessage("durable")
	codes, messages := sender.data(message)
	world.awaitDepositCalls(1)
	select {
	case code := <-codes:
		t.Fatalf("a reply %d before evs confirmed the deposit", code)
	default:
	}
	close(hold)
	if code := <-codes; code != 250 {
		t.Fatalf("reply %d %s", code, <-messages)
	}
	deposits := world.takenDeposits()
	if len(deposits) != 1 || !bytes.Equal(deposits[0].message, message) {
		t.Fatalf("deposits %+v", deposits)
	}
	trailer := deposits[0].trailer
	if trailer.GetVersion() != mailFormatVersion || !bytes.Equal(trailer.GetReceiverSidecarId(), testMailSessionReceiverId.Bytes()) ||
		!slices.Equal(trailer.GetRecipients(), []string{testMailSessionAlice}) || string(trailer.GetMailFrom()) != "bounce@sender.example" ||
		trailer.GetIngress().GetSni() != testMailReceiverServerName || trailer.GetTlsVersion() != tls.VersionTLS13 || trailer.GetTlsSuite() == 0 {
		t.Fatalf("trailer %v", trailer)
	}
	if trailer.GetEvidence() != nil {
		t.Fatal("evidence with no checker")
	}
}

// Every way a deposit fails answers 451 4.3.0, never a 5xx and never 530: a drop key still pending, §11.8's closed
// gate, §11.13's write-budget refusal, and a failure of any other kind.
func TestMailSessionDepositFailureAnswers451(t *testing.T) {
	failures := []error{
		fmt.Errorf("%w: no drop key yet", ErrGkmWait),
		&EvsError{Status: 412, Code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED},
		&EvsError{Status: 429, Code: protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT},
		errors.New("a synthetic transport failure"),
	}
	for _, failure := range failures {
		world := newMailSessionTestWorld(t, nil)
		world.depositErr = failure
		sender := world.open(testMailSessionIngress(t))
		sender.envelope(testMailSessionAlice)
		codes, messages := sender.data(testMailSessionMessage("failing"))
		code, message := <-codes, <-messages
		if code != 451 || !strings.HasPrefix(message, "4.3.0") {
			t.Errorf("%v: %d %s", failure, code, message)
		}
		if 0 < len(world.takenDeposits()) {
			t.Errorf("%v: a deposit committed", failure)
		}
	}
}

// A recipient's repo this receiver's own verified state gives no deposit, as a member's consented device's mailbox
// before anything marks it mail_send (owner decision 333), is answered 451 4.3.0 at DATA at once: no repo's deposit
// starts and no evs refusal is waited out, where evs's client would retry the exchange's refusal for most of a
// minute, past a sender's wait; the sender's next transaction, once the state gives the deposit, is taken.
func TestMailSessionAnswers451AtOnceWhereTheReceiverMayNotDeposit(t *testing.T) {
	spools := &mailSessionTestSpoolCount{}
	world := newMailSessionTestWorld(t, func(args *MailSessionArgs) {
		spools.SidecarStore = args.SpoolStore
		args.SpoolStore = spools
	})
	world.stateLock.Lock()
	world.refusedRepos = map[Id]bool{world.recipients[testMailSessionAlice].RepoId: true}
	world.stateLock.Unlock()
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice, testMailSessionBob)
	codes, messages := sender.data(testMailSessionMessage("not depositable"))
	if code, message := <-codes, <-messages; code != 451 || !strings.HasPrefix(message, "4.3.0") {
		t.Fatalf("DATA answered %d %s", code, message)
	}
	if calls, _ := world.depositCalls.Get(); calls != 0 {
		t.Fatalf("%d deposits reached a repo", calls)
	}
	if count := spools.count(); count != 0 {
		t.Fatalf("the refused message's body was spooled: %d spool files", count)
	}
	world.stateLock.Lock()
	world.refusedRepos = nil
	world.stateLock.Unlock()
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	sender.expect("RCPT TO:<"+testMailSessionAlice+">", 250)
	codes, messages = sender.data(testMailSessionMessage("depositable"))
	if code, message := <-codes, <-messages; code != 250 {
		t.Fatalf("DATA answered %d %s once the deposit was given", code, message)
	}
	if deposits := world.takenDeposits(); len(deposits) != 1 {
		t.Errorf("%d deposits taken", len(deposits))
	}
	if count := spools.count(); count == 0 {
		t.Error("the taken message was never spooled")
	}
}

// A spool store that counts the spool files it is asked to create.
type mailSessionTestSpoolCount struct {
	SidecarStore
	stateLock sync.Mutex
	creates   int
}

func (self *mailSessionTestSpoolCount) Create(name string) (SidecarStoreWriter, error) {
	if strings.HasPrefix(name, mailSpoolDirectory) {
		self.stateLock.Lock()
		self.creates += 1
		self.stateLock.Unlock()
	}
	return self.SidecarStore.Create(name)
}

func (self *mailSessionTestSpoolCount) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.creates
}

// A session that ends while evs holds its deposit, as a crash before durability ends it, gets no 250, and the
// deposit's push never commits.
func TestMailSessionEndingBeforeTheDepositIsDurableCommitsNothing(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	world.hold = make(chan struct{})
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice)
	codes, _ := sender.data(testMailSessionMessage("cut"))
	world.awaitDepositCalls(1)
	// the receiver's listen ends, which ends every session's context
	world.listener.Close()
	if code := <-codes; code == 250 {
		t.Fatal("a 250 for a deposit that never committed")
	}
	if 0 < len(world.takenDeposits()) {
		t.Fatal("a deposit committed after its session ended")
	}
}

// RCPT's answers: unknown 550 5.1.1; a lookup that failed or mailcfg not synced 451 4.3.0; a full network 452 4.2.2;
// past mail_inbound_recipients 452 4.5.3; a repo past mail_inbound_repos_per_message 452 4.5.3, a group counting
// once.
func TestMailSessionRcptRefusals(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	sender := world.open(testMailSessionIngress(t))
	sender.expect("EHLO mail.sender.example", 250)
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	if message := sender.expect("RCPT TO:<nobody@lbl0000001.root.example>", 550); !strings.HasPrefix(message, "5.1.1") {
		t.Errorf("unknown: %s", message)
	}
	sender.expect("RCPT TO:<"+testMailSessionAlice+">", 250)
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.resolveErr = ErrMailConfigNotSynced
	}()
	if message := sender.expect("RCPT TO:<"+testMailSessionBob+">", 451); !strings.HasPrefix(message, "4.3.0") {
		t.Errorf("not synced: %s", message)
	}
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.resolveErr = nil
		world.status = &MailNetworkStatus{Enabled: true, StorageFull: true}
	}()
	// the status read at alice's RCPT is fresh for StatusInterval, so the full network shows once it passes
	sender.expect("RCPT TO:<"+testMailSessionBob+">", 250)
	world.clock.Advance(30 * time.Second)
	if message := sender.expect("RCPT TO:<"+testMailSessionCarol+">", 452); !strings.HasPrefix(message, "4.2.2") {
		t.Errorf("full: %s", message)
	}

	world = newMailSessionTestWorld(t, nil)
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.limits[mailLimitInboundRecipients] = 3
		world.limits[mailLimitInboundReposPerMessage] = 2
		group := NewId()
		world.recipients["g1@lbl0000001.root.example"] = &MailSessionRecipient{Known: true, Address: "g1@lbl0000001.root.example", RepoId: group}
		world.recipients["g2@lbl0000001.root.example"] = &MailSessionRecipient{Known: true, Address: "g2@lbl0000001.root.example", RepoId: group}
	}()
	sender = world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice, "g1@lbl0000001.root.example")
	// a second address of the group's repo counts no new repo
	sender.expect("RCPT TO:<g2@lbl0000001.root.example>", 250)
	if message := sender.expect("RCPT TO:<"+testMailSessionBob+">", 452); !strings.HasPrefix(message, "4.5.3") {
		t.Errorf("recipients: %s", message)
	}
	sender.expect("RSET", 250)
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	sender.expect("RCPT TO:<"+testMailSessionAlice+">", 250)
	sender.expect("RCPT TO:<"+testMailSessionBob+">", 250)
	if message := sender.expect("RCPT TO:<"+testMailSessionCarol+">", 452); !strings.HasPrefix(message, "4.5.3") {
		t.Errorf("a third repo: %s", message)
	}
}

// The network's postmaster@, which §15.8 makes an alias of admin's mailbox: the full address of the bare form under the
// test's SNI, mx.lbl0000001.root.example.
const testMailSessionPostmaster = "postmaster@lbl0000001.root.example"

// A session world whose mailcfg knows postmaster@ in each of zones, a repo for them all, and which keeps every address
// Resolve is asked about; mutate changes its args further.
func newMailSessionPostmasterTestWorld(t *testing.T, zones []string, mutate func(args *MailSessionArgs)) (*mailSessionTestWorld, func() []string) {
	t.Helper()
	resolvedLock := sync.Mutex{}
	resolved := []string{}
	world := newMailSessionTestWorld(t, func(args *MailSessionArgs) {
		resolve := args.Resolve
		args.Resolve = func(ctx context.Context, address string) (*MailSessionRecipient, error) {
			func() {
				resolvedLock.Lock()
				defer resolvedLock.Unlock()
				resolved = append(resolved, address)
			}()
			return resolve(ctx, address)
		}
		if mutate != nil {
			mutate(args)
		}
	})
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		adminRepoId := NewId()
		for _, zone := range zones {
			address := "postmaster@" + zone
			world.recipients[address] = &MailSessionRecipient{Known: true, Address: address, RepoId: adminRepoId}
		}
	}()
	return world, func() []string {
		resolvedLock.Lock()
		defer resolvedLock.Unlock()
		return slices.Clone(resolved)
	}
}

// RFC 5321's bare RCPT TO:<Postmaster>, in any ASCII case, is postmaster at the domain of the MX host the sender
// reached, its SNI less the host's first label (owner decision 446). A receiver serving several domains picks the one
// the sender's SNI names: the network's zone for mx.<net>.<root>, an alias's for the alias's mx host and a scope's for
// the scope's. Resolve is asked for that full address, the RCPT answered 250 and the deposit's trailer names it, as
// when the sender writes the address whole, and the receiver's own zone is never asked for.
func TestMailSessionTakesABarePostmasterAtTheDomainTheSenderReached(t *testing.T) {
	for _, zone := range []string{"lbl0000001.root.example", "alias000001.root.example", "ops.lbl0000001.root.example"} {
		postmaster := "postmaster@" + zone
		world, resolved := newMailSessionPostmasterTestWorld(t, []string{zone}, func(args *MailSessionArgs) {
			args.PostmasterDomain = func(ctx context.Context) (string, error) {
				return "", errors.New("the receiver's own zone was asked for in a session with an SNI")
			}
		})
		sender := world.openNaming(testMailSessionIngress(t), "mx."+zone)
		sender.envelope("Postmaster", "postmaster", "POSTMASTER", postmaster)
		codes, messages := sender.data(testMailSessionMessage("bare"))
		if code := <-codes; code != 250 {
			t.Fatalf("%s: reply %d %s", zone, code, <-messages)
		}
		want := []string{postmaster, postmaster, postmaster, postmaster}
		if got := resolved(); !slices.Equal(got, want) {
			t.Errorf("%s: Resolve was asked for %q", zone, got)
		}
		deposits := world.takenDeposits()
		if len(deposits) != 1 || !slices.Equal(deposits[0].trailer.GetRecipients(), want) {
			t.Fatalf("%s: deposits %+v", zone, deposits)
		}
	}
}

// The bare form counts against mail_inbound_recipients and mail_inbound_repos_per_message as the full address does:
// with room for two recipients, one of each fills a transaction, after which either gets 452 4.5.3; with room for one
// repo, after alice's either form of postmaster gets 452 4.5.3 for its repo.
func TestMailSessionCountsABarePostmasterAsTheFullAddress(t *testing.T) {
	full := "<" + testMailSessionPostmaster + ">"
	world, _ := newMailSessionPostmasterTestWorld(t, []string{"lbl0000001.root.example"}, nil)
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.limits[mailLimitInboundRecipients] = 2
	}()
	sender := world.open(testMailSessionIngress(t))
	sender.expect("EHLO mail.sender.example", 250)
	for _, paths := range [][]string{{"<Postmaster>", full}, {full, "<Postmaster>"}} {
		sender.expect("MAIL FROM:<bounce@sender.example>", 250)
		for _, path := range paths {
			sender.expect("RCPT TO:"+path, 250)
		}
		for _, path := range paths {
			if message := sender.expect("RCPT TO:"+path, 452); !strings.HasPrefix(message, "4.5.3") {
				t.Errorf("%s past the recipients: %s", path, message)
			}
		}
		sender.expect("RSET", 250)
	}

	world, _ = newMailSessionPostmasterTestWorld(t, []string{"lbl0000001.root.example"}, nil)
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.limits[mailLimitInboundReposPerMessage] = 1
	}()
	sender = world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice)
	for _, path := range []string{"<Postmaster>", full} {
		if message := sender.expect("RCPT TO:"+path, 452); !strings.HasPrefix(message, "4.5.3") {
			t.Errorf("%s past the repos: %s", path, message)
		}
	}
}

// Every other answer RCPT gives the full address, the bare form gets too: 550 5.1.1 while mailcfg knows no
// postmaster@, 451 4.3.0 while mailcfg is not synced, and 452 4.2.2 for a full network.
func TestMailSessionAnswersABarePostmasterAsTheFullAddress(t *testing.T) {
	full := "<" + testMailSessionPostmaster + ">"
	world, _ := newMailSessionPostmasterTestWorld(t, nil, nil)
	sender := world.open(testMailSessionIngress(t))
	sender.expect("EHLO mail.sender.example", 250)
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	for _, path := range []string{"<Postmaster>", full} {
		if message := sender.expect("RCPT TO:"+path, 550); !strings.HasPrefix(message, "5.1.1") {
			t.Errorf("%s unknown: %s", path, message)
		}
	}

	world, _ = newMailSessionPostmasterTestWorld(t, []string{"lbl0000001.root.example"}, nil)
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.resolveErr = ErrMailConfigNotSynced
	}()
	sender = world.open(testMailSessionIngress(t))
	sender.expect("EHLO mail.sender.example", 250)
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	for _, path := range []string{"<Postmaster>", full} {
		if message := sender.expect("RCPT TO:"+path, 451); !strings.HasPrefix(message, "4.3.0") {
			t.Errorf("%s not synced: %s", path, message)
		}
	}
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.resolveErr = nil
		world.status = &MailNetworkStatus{Enabled: true, StorageFull: true}
	}()
	for _, path := range []string{"<Postmaster>", full} {
		if message := sender.expect("RCPT TO:"+path, 452); !strings.HasPrefix(message, "4.2.2") {
			t.Errorf("%s full: %s", path, message)
		}
	}
}

// With no SNI, as a direct-MX sender may send none, the bare form is postmaster at the receiver's own zone from
// PostmasterDomain, its answer lowercased and its final dot dropped. An error there answers 451 4.3.0, as Resolve's
// does, and an empty answer, or no PostmasterDomain at all, leaves the bare form unknown, 550 5.1.1, while the full
// address is still taken.
func TestMailSessionTakesABarePostmasterWithNoSniAtTheReceiversZone(t *testing.T) {
	noSni, err := proto.Marshal(&protocol.MailIngress{
		Version:    mailFormatVersion,
		SenderIp:   []byte{192, 0, 2, 25},
		SenderPort: 40000,
		EhloName:   "mail.sender.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	type answer struct {
		domain string
		err    error
	}
	answerLock := sync.Mutex{}
	current := answer{}
	world, resolved := newMailSessionPostmasterTestWorld(t, []string{"lbl0000001.root.example"}, func(args *MailSessionArgs) {
		args.PostmasterDomain = func(ctx context.Context) (string, error) {
			answerLock.Lock()
			defer answerLock.Unlock()
			return current.domain, current.err
		}
	})
	setAnswer := func(next answer) {
		answerLock.Lock()
		defer answerLock.Unlock()
		current = next
	}
	sender := world.openNaming(noSni, "")
	sender.expect("EHLO mail.sender.example", 250)
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	setAnswer(answer{domain: "LBL0000001.Root.Example."})
	sender.expect("RCPT TO:<Postmaster>", 250)
	if got := resolved(); !slices.Equal(got, []string{testMailSessionPostmaster}) {
		t.Errorf("Resolve was asked for %q", got)
	}
	setAnswer(answer{err: errors.New("the zone is not there to read")})
	if message := sender.expect("RCPT TO:<Postmaster>", 451); !strings.HasPrefix(message, "4.3.0") {
		t.Errorf("a zone not there to read: %s", message)
	}
	setAnswer(answer{})
	if message := sender.expect("RCPT TO:<Postmaster>", 550); !strings.HasPrefix(message, "5.1.1") {
		t.Errorf("no zone: %s", message)
	}
	sender.expect("RCPT TO:<"+testMailSessionPostmaster+">", 250)
	if got := resolved(); !slices.Equal(got, []string{testMailSessionPostmaster, testMailSessionPostmaster}) {
		t.Errorf("Resolve was asked for %q", got)
	}

	world, _ = newMailSessionPostmasterTestWorld(t, []string{"lbl0000001.root.example"}, nil)
	sender = world.openNaming(noSni, "")
	sender.expect("EHLO mail.sender.example", 250)
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	if message := sender.expect("RCPT TO:<Postmaster>", 550); !strings.HasPrefix(message, "5.1.1") {
		t.Errorf("no PostmasterDomain: %s", message)
	}
	sender.expect("RCPT TO:<"+testMailSessionPostmaster+">", 250)
}

// EHLO's answer: SIZE at the network's limit, 8BITMIME, SMTPUTF8, PIPELINING, CHUNKING, ENHANCEDSTATUSCODES and
// REQUIRETLS, and no AUTH, STARTTLS or LIMITS.
func TestMailSessionEhloAdvertisesTheReceiversExtensions(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	sender := world.open(testMailSessionIngress(t))
	message := sender.expect("EHLO mail.sender.example", 250)
	lines := strings.Split(message, "\n")
	for _, want := range []string{"SIZE 52428800", "8BITMIME", "SMTPUTF8", "PIPELINING", "CHUNKING", "ENHANCEDSTATUSCODES", "REQUIRETLS"} {
		if !slices.Contains(lines, want) {
			t.Errorf("EHLO lacks %s: %q", want, lines)
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "AUTH") || strings.HasPrefix(line, "STARTTLS") || strings.HasPrefix(line, "LIMITS") {
			t.Errorf("EHLO offers %s", line)
		}
	}
}

// The receiver's bounds hold whatever the answer's enforced says, as the closure floor and pacing do (QD-1023, beside
// owner decision 520): dark or enforced, EHLO advertises SIZE at mail_inbound_message_bytes and a RCPT past
// mail_inbound_recipients answers 452 4.5.3.
func TestMailSessionBoundsHoldWhateverEnforcedSays(t *testing.T) {
	for _, enforced := range []bool{false, true} {
		world := newMailSessionTestWorld(t, nil)
		func() {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			world.enforced = enforced
			world.limits[mailLimitInboundRecipients] = 1
		}()
		sender := world.open(testMailSessionIngress(t))
		if lines := strings.Split(sender.expect("EHLO mail.sender.example", 250), "\n"); !slices.Contains(lines, "SIZE 52428800") {
			t.Errorf("enforced %t: EHLO %q", enforced, lines)
		}
		sender.expect("MAIL FROM:<bounce@sender.example>", 250)
		sender.expect("RCPT TO:<"+testMailSessionAlice+">", 250)
		if message := sender.expect("RCPT TO:<"+testMailSessionBob+">", 452); !strings.HasPrefix(message, "4.5.3") {
			t.Errorf("enforced %t: a second recipient past one: %s", enforced, message)
		}
	}
}

// With no limits to read, EHLO answers 451 4.3.0, never an unbounded SIZE.
func TestMailSessionWithoutLimitsAnswers451(t *testing.T) {
	for _, limits := range []map[string]int64{nil, {mailLimitInboundRecipients: 100, mailLimitInboundReposPerMessage: 8}} {
		world := newMailSessionTestWorld(t, nil)
		func() {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			if limits == nil {
				world.limitsErr = errors.New("synthetic api outage")
			} else {
				world.limits = limits
			}
		}()
		sender := world.open(testMailSessionIngress(t))
		if message := sender.expect("EHLO mail.sender.example", 451); !strings.HasPrefix(message, "4.3.0") {
			t.Errorf("limits %v: %s", limits, message)
		}
	}
}

// Each repo's deposit names its own recipients alone, so a recipient of one repo learns nothing of another's, a BCC
// included.
func TestMailSessionEachRepoLearnsOnlyItsOwnRecipients(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	shared := world.recipients[testMailSessionAlice].RepoId
	world.recipients[testMailSessionBob].RepoId = shared
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice, testMailSessionCarol, testMailSessionBob)
	codes, _ := sender.data(testMailSessionMessage("bcc"))
	if code := <-codes; code != 250 {
		t.Fatalf("reply %d", code)
	}
	deposits := world.takenDeposits()
	if len(deposits) != 2 {
		t.Fatalf("%d deposits", len(deposits))
	}
	for _, deposit := range deposits {
		want := []string{testMailSessionCarol}
		if deposit.repoId == shared {
			want = []string{testMailSessionAlice, testMailSessionBob}
		}
		if !slices.Equal(deposit.trailer.GetRecipients(), want) {
			t.Errorf("repo %s's trailer names %v", deposit.repoId, deposit.trailer.GetRecipients())
		}
	}
}

// A forwarder answering TXT queries from records, and NXDOMAIN with no SOA otherwise, so nothing is cached.
type mailSessionTestForwarder struct {
	records map[string]string
}

func (self *mailSessionTestForwarder) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	name := dnsmessage.MustNewName(domain + ".")
	value, found := self.records[strings.ToLower(domain)]
	rcode := dnsmessage.RCodeNameError
	if found && qType == dnsmessage.TypeTXT {
		rcode = dnsmessage.RCodeSuccess
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: rcode})
	builder.StartQuestions()
	builder.Question(dnsmessage.Question{Name: name, Type: qType, Class: dnsmessage.ClassINET})
	builder.StartAnswers()
	if rcode == dnsmessage.RCodeSuccess {
		builder.TXTResource(dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 300},
			dnsmessage.TXTResource{TXT: []string{value}})
	}
	reply, err := builder.Finish()
	if err != nil {
		return nil, false
	}
	return reply, true
}

// SPF fail and a DMARC reject refuse nothing: the message is deposited and answered 250, its evidence sealed with
// those verdicts, bound to its hash and this receiver.
func TestMailSessionNoAuthenticationResultRefusesMail(t *testing.T) {
	clock := (*mailReceiverTestClock)(nil)
	world := newMailSessionTestWorld(t, func(args *MailSessionArgs) {
		clock = args.Clock.(*mailReceiverTestClock)
		settings := DefaultMailAuthSettings()
		forwarder := &mailSessionTestForwarder{records: map[string]string{
			"sender.example":        "v=spf1 -all",
			"_dmarc.sender.example": "v=DMARC1; p=reject",
		}}
		args.Checker = NewMailAuthChecker(NewMailDnsStub(forwarder, clock, settings), clock, settings)
		args.Slots = NewMailAuthSlots(settings)
	})
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice)
	message := testMailSessionMessage("spoofed")
	codes, messages := sender.data(message)
	if code := <-codes; code != 250 {
		t.Fatalf("an authentication result refused mail: %d %s", code, <-messages)
	}
	deposits := world.takenDeposits()
	if len(deposits) != 1 {
		t.Fatalf("%d deposits", len(deposits))
	}
	evidence := deposits[0].trailer.GetEvidence()
	messageSha256 := sha256.Sum256(message)
	if evidence == nil || !bytes.Equal(evidence.GetMessageSha256(), messageSha256[:]) ||
		!bytes.Equal(evidence.GetReceiverSidecarId(), testMailSessionReceiverId.Bytes()) {
		t.Fatalf("evidence %v", evidence)
	}
	if evidence.GetSpf().GetResult() != protocol.SpfVerdict_SPF_FAIL || evidence.GetDmarc().GetResult() != protocol.DmarcVerdict_DMARC_FAIL {
		t.Errorf("verdicts spf %v dmarc %v", evidence.GetSpf().GetResult(), evidence.GetDmarc().GetResult())
	}
}

// BDAT in segments: a message sent as chunks deposits whole, and RSET between chunks, mid-transfer, discards it, a
// later transaction on the session depositing normally.
func TestMailSessionBdatAndAResetMidTransfer(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice)
	message := testMailSessionMessage("chunked")
	half := len(message) / 2
	if err := sender.text.PrintfLine("BDAT %d", half); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.conn.Write(message[:half]); err != nil {
		t.Fatal(err)
	}
	if code, _ := sender.reply(); code != 250 {
		t.Fatalf("a chunk answered %d", code)
	}
	sender.expect("RSET", 250)
	if 0 < len(world.takenDeposits()) {
		t.Fatal("a message reset mid-transfer was deposited")
	}
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	sender.expect("RCPT TO:<"+testMailSessionAlice+">", 250)
	for index, part := range [][]byte{message[:half], message[half:]} {
		line := fmt.Sprintf("BDAT %d", len(part))
		if index == 1 {
			line += " LAST"
		}
		if err := sender.text.PrintfLine("%s", line); err != nil {
			t.Fatal(err)
		}
		if _, err := sender.conn.Write(part); err != nil {
			t.Fatal(err)
		}
		if code, reply := sender.reply(); code != 250 {
			t.Fatalf("chunk %d answered %d %s", index, code, reply)
		}
	}
	deposits := world.takenDeposits()
	if len(deposits) != 1 || !bytes.Equal(deposits[0].message, message) {
		t.Fatal("the chunked message did not deposit whole")
	}
}

// A message whose body has a 200 KiB line, far past RFC 5321's 1,000 octets, is taken whole: the line bound only
// holds a command's buffer.
func TestMailSessionTakesALongLine(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice)
	message := append(testMailSessionMessage("long line"), bytes.Repeat([]byte("x"), 200*1024)...)
	message = append(message, "\r\n"...)
	codes, _ := sender.data(message)
	if code := <-codes; code != 250 {
		t.Fatalf("a long line answered %d", code)
	}
	if deposits := world.takenDeposits(); len(deposits) != 1 || !bytes.Equal(deposits[0].message, message) {
		t.Fatal("the long-line message did not deposit whole")
	}
}

// MAIL must follow the handshake within 60 s: a session idle that long is closed.
func TestMailSessionClosesWithoutMailWithin60Seconds(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	opened := world.clock.Now()
	sender := world.open(testMailSessionIngress(t))
	sender.expect("EHLO mail.sender.example", 250)
	world.clock.awaitWaitAt(opened.Add(60 * time.Second))
	world.clock.Advance(60 * time.Second)
	if _, err := sender.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the session lived past 60 s with no MAIL")
	}
}

// A stream with no MailIngress, or one of an unknown version, closes before a reply.
func TestMailSessionClosesAStreamWithoutTheRoutersIngress(t *testing.T) {
	unknownVersion, err := proto.Marshal(&protocol.MailIngress{Version: 2, SenderIp: []byte{192, 0, 2, 25}})
	if err != nil {
		t.Fatal(err)
	}
	for _, metadata := range [][]byte{nil, []byte("not an ingress"), unknownVersion, bytes.Repeat([]byte{0x12, 0x01, 0x01}, 400)} {
		world := newMailSessionTestWorld(t, nil)
		sender := world.open(metadata)
		if code, _ := sender.command("EHLO mail.sender.example"); code != 0 {
			t.Errorf("a stream without the router's ingress answered %d", code)
		}
	}
}

// ParseMailIngress holds the router's bound, version and field shapes.
func TestParseMailIngressRefusesWhatIsNotTheRouters(t *testing.T) {
	good := &protocol.MailIngress{Version: 1, SenderIp: bytes.Repeat([]byte{1}, 16), SenderPort: 25, Sni: "mx.example"}
	encoded, err := proto.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMailIngress(encoded, 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMailIngress(encoded, len(encoded)-1); !errors.Is(err, ErrMailIngressInvalid) {
		t.Errorf("past its bound: %v", err)
	}
	for _, bad := range []*protocol.MailIngress{
		{Version: 1, SenderIp: []byte{1, 2, 3}},
		{Version: 1, SenderIp: []byte{1, 2, 3, 4}, SenderPort: 65536},
		{Version: 0, SenderIp: []byte{1, 2, 3, 4}},
	} {
		encoded, err := proto.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseMailIngress(encoded, 1024); !errors.Is(err, ErrMailIngressInvalid) {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

// A 50 MiB message in 64 KiB BDAT segments, the largest mail_inbound_message_bytes allows, deposits whole through
// the spool: the plaintext evs gets is the message as sent, its trailer and the trailer's length.
func TestMailSessionTakesAFiftyMebibyteMessageInSegments(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice)
	const segmentByteCount = 64 * 1024
	const messageByteCount = 50 * 1024 * 1024
	segment := testMailSpoolBytes(segmentByteCount, 17)
	hash := sha256.New()
	for written := 0; written < messageByteCount; written += segmentByteCount {
		segment[0] = byte(written / segmentByteCount)
		hash.Write(segment)
		line := fmt.Sprintf("BDAT %d", segmentByteCount)
		if written+segmentByteCount == messageByteCount {
			line += " LAST"
		}
		if err := sender.text.PrintfLine("%s", line); err != nil {
			t.Fatal(err)
		}
		if _, err := sender.conn.Write(segment); err != nil {
			t.Fatal(err)
		}
		if code, reply := sender.reply(); code != 250 {
			t.Fatalf("a segment at %d answered %d %s", written, code, reply)
		}
	}
	deposits := world.takenDeposits()
	if len(deposits) != 1 {
		t.Fatalf("%d deposits", len(deposits))
	}
	ingress, err := ParseMailIngress(testMailSessionIngress(t), 1024)
	if err != nil {
		t.Fatal(err)
	}
	state := sender.conn.ConnectionState()
	trailer, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailDeposit{
		Version:           mailFormatVersion,
		Ingress:           ingress,
		MailFrom:          []byte("bounce@sender.example"),
		Recipients:        []string{testMailSessionAlice},
		TlsVersion:        uint32(state.Version),
		TlsSuite:          uint32(state.CipherSuite),
		ReceiverSidecarId: testMailSessionReceiverId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	hash.Write(trailer)
	hash.Write([]byte{byte(len(trailer) >> 24), byte(len(trailer) >> 16), byte(len(trailer) >> 8), byte(len(trailer))})
	if deposits[0].size != int64(messageByteCount+len(trailer)+4) || deposits[0].sha256 != [sha256.Size]byte(hash.Sum(nil)) {
		t.Fatal("the 50 MiB message did not deposit as sent")
	}
}
