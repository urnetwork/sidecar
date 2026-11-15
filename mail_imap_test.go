//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension && !windows

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
)

// The time a test's mailbox starts at.
const testMailImapBaseMillis = uint64(1793923200000)

// One network's mailbox behind the server, its credential made.
type testMailImapNetwork struct {
	mailbox *mailTestStore
	store   *MailImapStore
	secret  string
	account *MailImapAccount
	hints   *MonitorValue[uint64]
}

// A network whose mailbox holds messages 1 to count.
func newTestMailImapNetwork(t *testing.T, clock Clock, networkId Id, count uint64) *testMailImapNetwork {
	t.Helper()
	mailbox := newMailTestStore()
	for n := uint64(1); n <= count; n += 1 {
		testMailImapDeliver(t, mailbox, n, testMailImapBaseMillis+n*1000)
	}
	store, err := NewMailImapStore(&MailImapStoreArgs{
		MailboxId: testMailMailboxId,
		Mailbox:   mailbox,
		Hlc:       NewMailHlc(clock),
		SidecarId: testMailImapSidecarId,
		State:     newTestMemoryStore(),
		Clock:     clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewMailLocalCredential(&testMailSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewMailLocalCredentialSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.Install(secret.Verifier); err != nil {
		t.Fatal(err)
	}
	hints := NewMonitorValue(uint64(0))
	return &testMailImapNetwork{
		mailbox: mailbox,
		store:   store,
		secret:  secret.Text,
		hints:   hints,
		account: &MailImapAccount{
			NetworkId:  networkId,
			Credential: credential,
			Store:      func() (*MailImapStore, error) { return store, nil },
			Hints:      hints.Get,
		},
	}
}

// What go-imap logged, which a test reads for a panic it recovered.
type testMailImapLog struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testMailImapLog) Printf(format string, args ...interface{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, fmt.Sprintf(format, args...))
}

// The lines that tell of a panic.
func (self *testMailImapLog) panics() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	panics := []string{}
	for _, line := range self.lines {
		if strings.HasPrefix(line, "panic") {
			panics = append(panics, line)
		}
	}
	return panics
}

// A listener a test hands connections to.
type testMailImapListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newTestMailImapListener() *testMailImapListener {
	return &testMailImapListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (self *testMailImapListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

func (self *testMailImapListener) Close() error {
	self.once.Do(func() { close(self.closed) })
	return nil
}

func (self *testMailImapListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

// Hands conn to the server, as the daemon's listener would with these readings of it.
func (self *testMailImapListener) offer(t *testing.T, conn net.Conn, loopback bool, isTls bool) {
	t.Helper()
	select {
	case self.conns <- &DaemonLocalConn{Conn: conn, Loopback: loopback, Tls: isTls}:
	case <-time.After(30 * time.Second):
		t.Fatal("the server took no connection")
	}
}

// Networks behind one server on a loopback listener of the daemon's helper, and a listener a test feeds.
type testMailImapWorld struct {
	t     *testing.T
	clock Clock
	// the clock when the test moves it, nil for one of its own
	moved    *testMailCredentialClock
	networks []*testMailImapNetwork
	server   *MailImapServer
	log      *testMailImapLog
	address  string
	fed      *testMailImapListener
}

// A world of one network holding two messages, on a clock the test moves.
func newTestMailImapWorld(t *testing.T, settings *MailImapServerSettings) *testMailImapWorld {
	t.Helper()
	moved := newTestMailCredentialClock(time.UnixMilli(int64(testMailImapBaseMillis) + 60000))
	world := newTestMailImapWorldOn(t, settings, moved)
	world.moved = moved
	return world
}

// A world of one network holding two messages, on clock.
func newTestMailImapWorldOn(t *testing.T, settings *MailImapServerSettings, clock Clock) *testMailImapWorld {
	t.Helper()
	world := &testMailImapWorld{t: t, clock: clock, log: &testMailImapLog{}, fed: newTestMailImapListener()}
	world.networks = append(world.networks, newTestMailImapNetwork(t, clock, testMailId(0xa1), 2))
	var err error
	world.server, err = newMailImapServer(context.Background(), &MailImapServerArgs{
		Accounts: func() []*MailImapAccount {
			accounts := []*MailImapAccount{}
			for _, network := range world.networks {
				accounts = append(accounts, network.account)
			}
			return accounts
		},
		Clock:    clock,
		Settings: settings,
	}, world.log)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalImap, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	world.address = listener.Addrs()[0].String()
	served := make(chan struct{}, 2)
	go func() {
		world.server.Serve(listener)
		served <- struct{}{}
	}()
	go func() {
		world.server.Serve(world.fed)
		served <- struct{}{}
	}()
	t.Cleanup(func() {
		world.server.Close()
		<-served
		<-served
		if panics := world.log.panics(); 0 < len(panics) {
			t.Errorf("go-imap recovered a panic: %v", panics)
		}
	})
	return world
}

// A stock client on the loopback listener.
func (self *testMailImapWorld) client(handler *imapclient.UnilateralDataHandler) *imapclient.Client {
	self.t.Helper()
	client, err := imapclient.DialInsecure(self.address, &imapclient.Options{UnilateralDataHandler: handler})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(func() { client.Close() })
	return client
}

// Waits until the clock holds a wait of timeout, then checks that nothing answered before it passes.
func (self *testMailImapWorld) passRefusal(answered chan error, timeout time.Duration) error {
	self.t.Helper()
	for !slices.Contains(self.moved.pending(), timeout) {
		select {
		case err := <-answered:
			self.t.Fatalf("a refusal answered before its wait: %v", err)
		case <-self.moved.added:
		}
	}
	select {
	case err := <-answered:
		self.t.Fatalf("a refusal answered before its wait: %v", err)
	default:
	}
	self.moved.Advance(timeout)
	return <-answered
}

// A stock client's transcript through LOGIN, SELECT, FETCH, STORE and IDLE: the messages arrive in UID order with
// their bytes, a \Seen stored reaches f/ for every device, a FETCH of BODY[] sets \Seen where BODY.PEEK[] does not,
// and a delivery during IDLE reaches the client as EXISTS on the mailbox's hint.
func TestMailImapStockClientTranscript(t *testing.T) {
	world := newTestMailImapWorld(t, nil)
	network := world.networks[0]
	exists := make(chan uint32, 8)
	client := world.client(&imapclient.UnilateralDataHandler{Mailbox: func(data *imapclient.UnilateralDataMailbox) {
		if data.NumMessages != nil {
			exists <- *data.NumMessages
		}
	}})
	if err := client.Login(MailLocalCredentialUser, network.secret).Wait(); err != nil {
		t.Fatal(err)
	}
	selected, err := client.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if selected.NumMessages != 2 || selected.UIDNext != 3 || selected.UIDValidity == 0 {
		t.Fatalf("select %+v", selected)
	}
	messages, err := client.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{
		UID: true, Flags: true, RFC822Size: true, BodySection: []*imap.FetchItemBodySection{{Peek: true}},
	}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].UID != 1 || messages[1].UID != 2 {
		t.Fatalf("fetched %d", len(messages))
	}
	for _, message := range messages {
		if slices.Contains(message.Flags, imap.FlagSeen) {
			t.Errorf("BODY.PEEK[] set \\Seen on %d", message.UID)
		}
		for _, body := range message.BodySection {
			if !strings.Contains(string(body.Bytes), "Subject: message") {
				t.Errorf("a body %q", body.Bytes)
			}
		}
	}
	stored, err := client.Store(imap.UIDSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}}, nil).Collect()
	if err != nil || len(stored) != 1 || !slices.Contains(stored[0].Flags, imap.FlagSeen) {
		t.Fatalf("store %v %v", stored, err)
	}
	flags, err := testMailView(network.mailbox, nil, nil).Flags(context.Background(), MailYearMonthOf(testMailImapBaseMillis+1000), testMailId(1))
	if err != nil || !flags.Seen {
		t.Fatalf("another device's view of \\Seen: %+v %v", flags, err)
	}
	read, err := client.Fetch(imap.UIDSetNum(2), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{{}}}).Collect()
	if err != nil || len(read) != 1 || !slices.Contains(read[0].Flags, imap.FlagSeen) {
		t.Fatalf("BODY[] answered %v %v", read, err)
	}
	if flags, err := testMailView(network.mailbox, nil, nil).Flags(context.Background(), MailYearMonthOf(testMailImapBaseMillis+2000), testMailId(2)); err != nil || !flags.Seen {
		t.Fatalf("BODY[]'s \\Seen in f/: %+v %v", flags, err)
	}

	idle, err := client.Idle()
	if err != nil {
		t.Fatal(err)
	}
	testMailImapDeliver(t, network.mailbox, 3, testMailImapBaseMillis+3000)
	network.hints.Update(func(revision uint64) uint64 { return revision + 1 })
	for count := uint32(0); count != 3; {
		select {
		case count = <-exists:
			if 3 < count {
				t.Fatalf("EXISTS %d", count)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("no EXISTS 3 during IDLE")
		}
	}
	if err := idle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := idle.Wait(); err != nil {
		t.Fatal(err)
	}
}

// The secret that matches names the network: a session reads its own network's mailbox and no other's.
func TestMailImapLoginNamesTheNetwork(t *testing.T) {
	world := newTestMailImapWorld(t, nil)
	world.networks = append(world.networks, newTestMailImapNetwork(t, world.clock, testMailId(0xa2), 3))
	for index, want := range []uint32{2, 3} {
		client := world.client(nil)
		if err := client.Login(MailLocalCredentialUser, world.networks[index].secret).Wait(); err != nil {
			t.Fatal(err)
		}
		selected, err := client.Select("INBOX", nil).Wait()
		if err != nil || selected.NumMessages != want {
			t.Errorf("network %d's session selected %+v %v", index, selected, err)
		}
	}
}

// A wrong credential is refused only after its cost on the clock, doubling with each refusal from the address, a
// wrong name costing what a wrong secret does; the right one opens at once.
func TestMailImapRefusesAWrongCredentialAtABoundedRate(t *testing.T) {
	world := newTestMailImapWorld(t, nil)
	settings := DefaultMailLocalCredentialSettings()
	client := world.client(nil)
	login := func(user string, password string) chan error {
		answered := make(chan error, 1)
		go func() { answered <- client.Login(user, password).Wait() }()
		return answered
	}
	if err := world.passRefusal(login(MailLocalCredentialUser, "wrong"), settings.FailureDelay); err == nil {
		t.Fatal("a wrong secret logged in")
	}
	if err := world.passRefusal(login("someone", world.networks[0].secret), 2*settings.FailureDelay); err == nil {
		t.Fatal("a wrong name logged in")
	}
	if err := client.Login(MailLocalCredentialUser, world.networks[0].secret).Wait(); err != nil {
		t.Fatalf("the credential after two refusals: %v", err)
	}
}

// The credential reaches no log: a session that logs in with it, one that offers a canary as its password, and a
// malformed command carrying the canary leave neither in the standard logger, which go-imap writes to when it has no
// logger of its own.
func TestMailImapCredentialCanaryInNoLog(t *testing.T) {
	logged := &testMailImapLogWriter{}
	writer := log.Writer()
	log.SetOutput(logged)
	defer log.SetOutput(writer)
	clock := newTestMailCredentialClock(time.UnixMilli(int64(testMailImapBaseMillis)))
	network := newTestMailImapNetwork(t, clock, testMailId(0xa1), 1)
	server, err := NewMailImapServer(context.Background(), &MailImapServerArgs{
		Accounts: func() []*MailImapAccount { return []*MailImapAccount{network.account} },
		Clock:    clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalImap, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		server.Serve(listener)
	}()
	defer func() {
		server.Close()
		<-served
	}()
	client, err := imapclient.DialInsecure(listener.Addrs()[0].String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Login(MailLocalCredentialUser, network.secret).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	client.Logout().Wait()

	canary := "canary-7f3e9a2b"
	refused, err := imapclient.DialInsecure(listener.Addrs()[0].String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer refused.Close()
	answered := make(chan error, 1)
	go func() { answered <- refused.Login(MailLocalCredentialUser, canary).Wait() }()
	for !slices.Contains(clock.pending(), DefaultMailLocalCredentialSettings().FailureDelay) {
		<-clock.added
	}
	clock.Advance(DefaultMailLocalCredentialSettings().FailureDelay)
	if err := <-answered; err == nil {
		t.Fatal("the canary logged in")
	}
	raw, err := net.Dial("tcp", listener.Addrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	raw.Write([]byte(canary + "\x00 " + network.secret + "\r\n"))
	io.Copy(io.Discard, raw)
	raw.Close()
	for _, value := range []string{network.secret, canary} {
		if strings.Contains(logged.String(), value) {
			t.Fatalf("a log holds %q", value)
		}
	}
}

// The standard logger's output, under a lock, since a session's goroutine may still write as the test reads.
type testMailImapLogWriter struct {
	stateLock sync.Mutex
	buffer    bytes.Buffer
}

func (self *testMailImapLogWriter) Write(p []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.buffer.Write(p)
}

func (self *testMailImapLogWriter) String() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.buffer.String()
}

// IMAP's listener hands go-imap a TLS connection as its *tls.Conn, over which a client logs in, and a loopback one
// plain, and closes a plain one off loopback unanswered: plaintext stays on loopback (§22.5's §5 row, D-MAIL-11).
func TestMailImapPlaintextOnlyOnLoopback(t *testing.T) {
	world := newTestMailImapWorld(t, nil)
	network := world.networks[0]

	// a plain connection off loopback gets no greeting, only a close
	plainServer, plainClient := net.Pipe()
	defer plainClient.Close()
	world.fed.offer(t, plainServer, false, false)
	if read, err := plainClient.Read(make([]byte, 64)); err == nil {
		t.Fatalf("a plain connection off loopback read %d bytes", read)
	}

	// a TLS one takes LOGIN, which go-imap allows because it reads the connection as TLS
	serverConfig, _, _, err := EvsGitSelfSignedTls([]string{"imap.example"}, world.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(serverConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	tlsServer, tlsClient := net.Pipe()
	world.fed.offer(t, tls.Server(tlsServer, serverConfig), false, true)
	client := imapclient.New(tls.Client(tlsClient, &tls.Config{ServerName: "imap.example", RootCAs: roots, Time: world.clock.Now}), nil)
	defer client.Close()
	if err := client.Login(MailLocalCredentialUser, network.secret).Wait(); err != nil {
		t.Fatalf("LOGIN over TLS: %v", err)
	}
	if selected, err := client.Select("INBOX", nil).Wait(); err != nil || selected.NumMessages != 2 {
		t.Fatalf("SELECT over TLS: %+v %v", selected, err)
	}

	// a connection marked TLS that is not one is closed, not served plain
	fakeServer, fakeClient := net.Pipe()
	defer fakeClient.Close()
	world.fed.offer(t, fakeServer, false, true)
	if read, err := fakeClient.Read(make([]byte, 64)); err == nil {
		t.Fatalf("a connection marked TLS but plain read %d bytes", read)
	}

	// a loopback one is served plain
	loopbackServer, loopbackClient := net.Pipe()
	world.fed.offer(t, loopbackServer, true, false)
	plain := imapclient.New(loopbackClient, nil)
	defer plain.Close()
	if err := plain.Login(MailLocalCredentialUser, network.secret).Wait(); err != nil {
		t.Fatalf("LOGIN on loopback: %v", err)
	}
}

// EXAMINE opens a folder read-only: STORE is refused, and a FETCH of BODY[] sets no \Seen.
func TestMailImapExamineChangesNothing(t *testing.T) {
	world := newTestMailImapWorld(t, nil)
	network := world.networks[0]
	client := world.client(nil)
	if err := client.Login(MailLocalCredentialUser, network.secret).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagFlagged}}, nil).Collect(); err == nil {
		t.Error("STORE under EXAMINE")
	}
	if _, err := client.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}).Collect(); err != nil {
		t.Fatal(err)
	}
	flags, err := testMailView(network.mailbox, nil, nil).Flags(context.Background(), MailYearMonthOf(testMailImapBaseMillis+1000), testMailId(1))
	if err != nil || flags.Seen || flags.Flagged {
		t.Fatalf("EXAMINE changed f/: %+v %v", flags, err)
	}
}

// An erased message leaves a client's selected folder at its next command, and its bytes are answered to no FETCH,
// since its keys are gone (§2.18).
func TestMailImapSessionExpungesAnErasedMessage(t *testing.T) {
	world := newTestMailImapWorld(t, nil)
	network := world.networks[0]
	expunged := make(chan uint32, 4)
	client := world.client(&imapclient.UnilateralDataHandler{Expunge: func(seqNum uint32) { expunged <- seqNum }})
	if err := client.Login(MailLocalCredentialUser, network.secret).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := network.store.PurgeMail(context.Background(), testMailMailboxId, []Id{testMailId(1)}); err != nil {
		t.Fatal(err)
	}
	if err := client.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	select {
	case seqNum := <-expunged:
		if seqNum != 1 {
			t.Errorf("EXPUNGE %d", seqNum)
		}
	default:
		t.Fatal("no EXPUNGE after an erasure")
	}
	messages, err := client.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{{Peek: true}}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].UID != 2 {
		t.Fatalf("after the erasure FETCH answered %d messages", len(messages))
	}
	if _, err := network.store.Body(context.Background(), &MailImapMessage{Key: MailImapKey{RepoId: testMailMailboxId, Month: MailYearMonthOf(testMailImapBaseMillis + 1000), Id: testMailId(1)}}); !errors.Is(err, ErrMailImapMessagePurged) {
		t.Fatalf("an erased message's bytes: %v", err)
	}
}

// Past ConnectionMaxCount a connection is answered BYE and closed, and a session's end gives its place back.
func TestMailImapSessionsAreBounded(t *testing.T) {
	settings := DefaultMailImapServerSettings()
	settings.ConnectionMaxCount = 1
	world := newTestMailImapWorld(t, settings)
	first, err := imapclient.DialInsecure(world.address, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", world.address)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(raw)
	raw.Close()
	if !strings.Contains(string(answer), "BYE") {
		t.Fatalf("a second connection read %q", answer)
	}
	first.Logout().Wait()
	first.Close()
	// the place comes back once the first session's end has run
	for {
		count, changed := world.server.sessions.Get()
		if count == 0 {
			break
		}
		<-changed
	}
	second, err := imapclient.DialInsecure(world.address, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.Noop().Wait(); err != nil {
		t.Fatalf("a connection after the first ended: %v", err)
	}
}

// The daemon's IMAP binds where --listen says and serves its accounts there, and with no account it opens no port.
func TestDaemonMailImapBindsWhereListenSays(t *testing.T) {
	directory := shortTestDirectory(t)
	local := DefaultSidecarSettings().LocalSettings
	// the OS picks the port, so a run beside another never collides on --port's default
	local.FirstPort = 0
	daemon, err := NewDaemon(context.Background(), &DaemonSettings{
		Instance:       "default",
		StateDirectory: filepath.Join(directory, "state"),
		SocketPath:     filepath.Join(directory, "run", "default.sock"),
		Local:          local,
		Version:        testDaemonVersion,
		Listen:         []string{"127.0.0.1"},
		Log:            NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ran := make(chan error, 1)
	go func() { ran <- daemon.Run() }()
	defer func() {
		daemon.Close()
		<-ran
	}()
	imapd := daemon.MailImap()
	accounts := []*MailImapAccount{}
	imapd.accounts = func() []*MailImapAccount { return accounts }
	if _, err := imapd.Start(); !errors.Is(err, ErrMailImapNoAccount) {
		t.Fatalf("a start with no account: %v", err)
	}
	if listeners := daemon.LocalListeners(); len(listeners) != 0 {
		t.Fatalf("no account opened %+v", listeners)
	}
	clock := newTestMailCredentialClock(time.UnixMilli(int64(testMailImapBaseMillis)))
	network := newTestMailImapNetwork(t, clock, testMailId(0xa1), 2)
	accounts = append(accounts, network.account)
	status, err := imapd.Start()
	if err != nil {
		t.Fatal(err)
	}
	if status.Service != DaemonLocalImap || status.LanExposed || len(status.Addresses) != 1 || !strings.HasPrefix(status.Addresses[0], "127.0.0.1:") {
		t.Fatalf("the listener %+v", status)
	}
	if again, err := imapd.Start(); err != nil || again.Addresses[0] != status.Addresses[0] {
		t.Fatalf("a second start %+v %v", again, err)
	}
	client, err := imapclient.DialInsecure(status.Addresses[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Login(MailLocalCredentialUser, network.secret).Wait(); err != nil {
		t.Fatal(err)
	}
	if selected, err := client.Select("INBOX", nil).Wait(); err != nil || selected.NumMessages != 2 {
		t.Fatalf("select %+v %v", selected, err)
	}
}

// A mailStore whose next read, once held, waits until released: how a test stops a reader in the middle of its read.
type testMailImapHeldStore struct {
	mailStore

	stateLock sync.Mutex
	entered   chan struct{}
	release   chan struct{}
}

// Holds the next read: entered closes once it has begun, and it goes on once release is closed.
func (self *testMailImapHeldStore) hold() (chan struct{}, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entered, self.release = make(chan struct{}), make(chan struct{})
	return self.entered, self.release
}

func (self *testMailImapHeldStore) Read(ctx context.Context, path string, maxByteCount int) ([]byte, uint64, error) {
	entered, release := func() (chan struct{}, chan struct{}) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entered, release := self.entered, self.release
		self.entered, self.release = nil, nil
		return entered, release
	}()
	if entered != nil {
		close(entered)
		<-release
	}
	return self.mailStore.Read(ctx, path, maxByteCount)
}

// go-imap leaves IDLE without waiting for the session's Idle when a client ends it with anything but DONE, so a poll
// IDLE began can still be reading when the next command or Close runs. Close waits for no read, and the poll, once it
// has read, applies nothing to the session Close ended. Before, the poll read on into the snapshot Close had dropped
// and panicked, which FuzzMailImap found as a client sent "DONE70" for DONE.
func TestMailImapIdlePollAfterCloseAppliesNothing(t *testing.T) {
	clock := newTestMailCredentialClock(time.UnixMilli(int64(testMailImapBaseMillis) + 60000))
	mailbox := newMailTestStore()
	testMailImapDeliver(t, mailbox, 1, testMailImapBaseMillis+1000)
	testMailImapDeliver(t, mailbox, 2, testMailImapBaseMillis+2000)
	held := &testMailImapHeldStore{mailStore: mailbox}
	store, err := NewMailImapStore(&MailImapStoreArgs{
		MailboxId: testMailMailboxId,
		Mailbox:   held,
		Hlc:       NewMailHlc(clock),
		SidecarId: testMailImapSidecarId,
		State:     newTestMemoryStore(),
		Clock:     clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewMailLocalCredential(&testMailSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewMailLocalCredentialSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.Install(secret.Verifier); err != nil {
		t.Fatal(err)
	}
	account := &MailImapAccount{NetworkId: testMailId(0xa1), Credential: credential, Store: func() (*MailImapStore, error) { return store, nil }}
	server, err := newMailImapServer(context.Background(), &MailImapServerArgs{
		Accounts: func() []*MailImapAccount { return []*MailImapAccount{account} },
		Clock:    clock,
	}, &testMailImapLog{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.sessions.Update(func(count int) int { return count + 1 })
	session := newMailImapSession(server, nil)
	if err := session.Login(MailLocalCredentialUser, secret.Text); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Select(MailImapFolderInbox, nil); err != nil {
		t.Fatal(err)
	}

	entered, release := held.hold()
	stop := make(chan struct{})
	idled := make(chan error, 1)
	go func() {
		// a zero writer: a poll that applied anything would write to it and fail
		idled <- session.Idle(&imapserver.UpdateWriter{}, stop)
	}()
	<-entered
	// go-imap's early return: IDLE stopped and the session closed while its poll reads
	close(stop)
	session.Close()
	close(release)
	if err := <-idled; err != nil {
		t.Fatalf("IDLE after its session closed: %v", err)
	}
	if count := server.sessions.Value(); count != 0 {
		t.Fatalf("%d sessions after the close", count)
	}
}

// Any bytes a client sends after a good LOGIN, or before one, end in replies and a close, never a panic go-imap
// recovers, and within a bounded answer.
func FuzzMailImap(f *testing.F) {
	for _, seed := range []string{
		"a LOGIN ur x\r\n",
		"a SELECT INBOX\r\nb FETCH 1:* (FLAGS BODY[])\r\n",
		"a SELECT INBOX\r\nb UID STORE 1 +FLAGS (\\Seen)\r\n",
		"a SELECT INBOX\r\nb SEARCH OR SUBJECT x NOT SEEN\r\n",
		"a SELECT INBOX\r\nb IDLE\r\nDONE\r\n",
		"a SELECT INBOX\r\nb FETCH *:1 BODY[1.2.HEADER.FIELDS (SUBJECT)]<0.10>\r\n",
		"a EXAMINE Trash\r\nb UID EXPUNGE 1:*\r\nc LIST \"\" *\r\n",
		"a APPEND INBOX {9999999999}\r\n",
		"{9999999999}\r\n",
	} {
		f.Add([]byte(seed), true)
		f.Add([]byte(seed), false)
	}
	f.Fuzz(func(t *testing.T, input []byte, loggedIn bool) {
		if 16*1024 < len(input) {
			return
		}
		// a world of its own, whose cleanup fails the input on any panic go-imap recovered, on a clock whose waits fire
		// at once, so a refused LOGIN answers rather than holding the pipe
		world := newTestMailImapWorldOn(t, nil, &mailTestClock{now: time.UnixMilli(int64(testMailImapBaseMillis))})
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		world.fed.offer(t, serverConn, true, false)
		answered := make(chan int, 1)
		go func() {
			read, _ := io.Copy(io.Discard, io.LimitReader(clientConn, 4*1024*1024))
			answered <- int(read)
		}()
		if loggedIn {
			clientConn.Write([]byte("z LOGIN " + MailLocalCredentialUser + " " + world.networks[0].secret + "\r\n"))
		}
		clientConn.Write(input)
		clientConn.Write([]byte("\r\nDONE\r\nz LOGOUT\r\n"))
		clientConn.Close()
		if read := <-answered; 1024*1024 < read {
			t.Errorf("an answer of %d bytes", read)
		}
		if panics := world.log.panics(); 0 < len(panics) {
			t.Fatalf("go-imap recovered a panic: %v", panics)
		}
	})
}
