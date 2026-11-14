//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-13's receiver on fakes of its listen, keys and POST /dns/key-record, over the in-memory stream seam and a
// fake clock: serving stays false until 2 TTLs after the key's TLSA went out; a self-signed leaf then §13's issued
// chain on the same key, every handshake answered; a rotation keeps the old key serving until the new key's TLSA is
// live, a restart inside that window serving nothing; a listen that waits on a person surfaces the approval and runs
// once it passes; the listen's end stops the receiver at once; a stream not from the edge is reset; and the key's
// private half reaches no request, no store and no stream but crypto/tls's signature.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The server name a sender's SNI carries: mx under the network's label.
const testMailReceiverServerName = "mx.lbl0000001.root.example"

// The network's identifier set as the receiver's names give it.
var testMailReceiverNames = []string{"*.lbl0000001.root.example", "lbl0000001.root.example"}

// A clock a test moves. Advance fires every wait it reaches, and awaitWaitAt is how a test learns, with no sleep,
// that a loop has armed its next wait.
type mailReceiverTestClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []*mailReceiverTestWait
	// raised at each After
	waitCount *MonitorValue[int]
}

type mailReceiverTestWait struct {
	at   time.Time
	fire chan time.Time
}

func newMailReceiverTestClock() *mailReceiverTestClock {
	return &mailReceiverTestClock{
		now:       time.Date(2026, time.November, 14, 9, 0, 0, 0, time.UTC),
		waitCount: NewMonitorValue(0),
	}
}

func (self *mailReceiverTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *mailReceiverTestClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fire := make(chan time.Time, 1)
	if timeout <= 0 {
		fire <- self.now
		return fire
	}
	self.waits = append(self.waits, &mailReceiverTestWait{at: self.now.Add(timeout), fire: fire})
	self.waitCount.Update(func(count int) int { return count + 1 })
	return fire
}

func (self *mailReceiverTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	fire := self.After(timeout)
	stopped := make(chan struct{})
	var once sync.Once
	done := false
	var doneLock sync.Mutex
	go func() {
		select {
		case <-fire:
			doneLock.Lock()
			run := !done
			done = true
			doneLock.Unlock()
			if run {
				function()
			}
		case <-stopped:
		}
	}()
	return func() bool {
		doneLock.Lock()
		defer doneLock.Unlock()
		if done {
			return false
		}
		done = true
		once.Do(func() { close(stopped) })
		return true
	}
}

// Moves the clock and fires every wait it reaches.
func (self *mailReceiverTestClock) Advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
	self.waits = slices.DeleteFunc(self.waits, func(wait *mailReceiverTestWait) bool {
		if self.now.Before(wait.at) {
			return false
		}
		wait.fire <- self.now
		return true
	})
}

// Blocks until a wait due exactly at stands.
func (self *mailReceiverTestClock) awaitWaitAt(at time.Time) {
	for {
		_, notify := self.waitCount.Get()
		found := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return slices.ContainsFunc(self.waits, func(wait *mailReceiverTestWait) bool { return wait.at.Equal(at) })
		}()
		if found {
			return
		}
		<-notify
	}
}

// A listener the test hands streams to.
type mailReceiverTestListener struct {
	edgeNetworkId Id
	conns         chan *SocketConn
	closed        chan struct{}
	closeOnce     sync.Once
	serving       *MonitorValue[bool]
}

func newMailReceiverTestListener(edgeNetworkId Id) *mailReceiverTestListener {
	return &mailReceiverTestListener{
		edgeNetworkId: edgeNetworkId,
		conns:         make(chan *SocketConn, 16),
		closed:        make(chan struct{}),
		serving:       NewMonitorValue(false),
	}
}

func (self *mailReceiverTestListener) AcceptSocket(ctx context.Context) (*SocketConn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (self *mailReceiverTestListener) SetServing(serving bool) {
	self.serving.Set(serving)
}

func (self *mailReceiverTestListener) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

func (self *mailReceiverTestListener) tlsEdgeNetworkId() (Id, bool) {
	return self.edgeNetworkId, true
}

// Blocks until the listener's serving reads want.
func (self *mailReceiverTestListener) awaitServing(want bool) {
	for {
		serving, notify := self.serving.Get()
		if serving == want {
			return
		}
		<-notify
	}
}

// The device key: a current key, a pending one, and an issued chain on a key once the test issues it.
type mailReceiverTestKeys struct {
	clock    Clock
	settings *SidecarTlsSettings

	stateLock sync.Mutex
	current   *TlsDeviceKey
	pending   *TlsDeviceKey
	issued    map[[sha256.Size]byte]*tls.Certificate
}

func newMailReceiverTestKeys(t *testing.T, clock Clock) *mailReceiverTestKeys {
	t.Helper()
	return &mailReceiverTestKeys{
		clock:    clock,
		settings: DefaultSidecarTlsSettings(),
		current:  newMailReceiverTestKey(t, clock),
		issued:   map[[sha256.Size]byte]*tls.Certificate{},
	}
}

func newMailReceiverTestKey(t *testing.T, clock Clock) *TlsDeviceKey {
	t.Helper()
	key, err := newTlsDeviceKey(clock.Now(), TlsKeyRotationNone)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (self *mailReceiverTestKeys) TlsKeys() (*TlsDeviceKey, *TlsDeviceKey, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current, self.pending, nil
}

func (self *mailReceiverTestKeys) TlsDeviceCertificate(names []string) (*tls.Certificate, error) {
	current, issued := func() (*TlsDeviceKey, *tls.Certificate) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.current, self.issued[self.current.SpkiSha256()]
	}()
	if issued != nil {
		return issued, nil
	}
	return newTlsSelfSignedCertificate(current, names, self.clock.Now(), self.settings)
}

// A rotation's successor, as the cert manager's rotation sets it.
func (self *mailReceiverTestKeys) rotate(t *testing.T) *TlsDeviceKey {
	t.Helper()
	pending := newMailReceiverTestKey(t, self.clock)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pending = pending
	return pending
}

// The successor's certificate installed, which promotes it and drops the key it replaces.
func (self *mailReceiverTestKeys) promote() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.current = self.pending
	self.pending = nil
}

// §13's chain on key: a leaf a test CA signed for names.
func (self *mailReceiverTestKeys) issue(t *testing.T, key *TlsDeviceKey, names []string) *tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := self.clock.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "synthetic test ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDer)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDer)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &tls.Certificate{Certificate: [][]byte{leafDer, caDer}, PrivateKey: key, Leaf: leaf}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.issued[key.SpkiSha256()] = certificate
	return certificate
}

// One POST /dns/key-record the receiver made.
type mailReceiverTestPublish struct {
	host       string
	spkiSha256 [sha256.Size]byte
	at         time.Time
}

// POST /dns/key-record, recorded.
type mailReceiverTestPublisher struct {
	clock Clock

	stateLock sync.Mutex
	published []*mailReceiverTestPublish
	err       error
	count     *MonitorValue[int]
}

func (self *mailReceiverTestPublisher) PublishKeyRecord(ctx context.Context, host string, key *TlsDeviceKey, identifierSet []string) error {
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.err != nil {
			return self.err
		}
		self.published = append(self.published, &mailReceiverTestPublish{host: host, spkiSha256: key.SpkiSha256(), at: self.clock.Now()})
		return nil
	}()
	self.count.Update(func(count int) int { return count + 1 })
	return err
}

func (self *mailReceiverTestPublisher) publishes() []*mailReceiverTestPublish {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.published)
}

// Blocks until the publisher has been called count times.
func (self *mailReceiverTestPublisher) awaitCount(count int) {
	for {
		called, notify := self.count.Get()
		if count <= called {
			return
		}
		<-notify
	}
}

// What a receiver runs on in a test.
type mailReceiverTestWorld struct {
	t             *testing.T
	ctx           context.Context
	cancel        context.CancelFunc
	clock         *mailReceiverTestClock
	edgeNetworkId Id
	keys          *mailReceiverTestKeys
	publisher     *mailReceiverTestPublisher
	store         *testMemoryStore
	// the listen's answers in order, the last repeating, and how many times it was asked
	listenLock    sync.Mutex
	listenAnswers []func() (MailReceiverListener, error)
	listenCalls   *MonitorValue[int]
	listener      *mailReceiverTestListener
	streams       chan *MailReceiverStream
	receiver      *MailReceiver
}

func newMailReceiverTestWorld(t *testing.T, store *testMemoryStore) *mailReceiverTestWorld {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	clock := newMailReceiverTestClock()
	if store == nil {
		store = newTestMemoryStore()
	}
	world := &mailReceiverTestWorld{
		t:             t,
		ctx:           ctx,
		cancel:        cancel,
		clock:         clock,
		edgeNetworkId: NewId(),
		keys:          newMailReceiverTestKeys(t, clock),
		publisher:     &mailReceiverTestPublisher{clock: clock, count: NewMonitorValue(0)},
		store:         store,
		listenCalls:   NewMonitorValue(0),
		streams:       make(chan *MailReceiverStream, 16),
	}
	world.listener = newMailReceiverTestListener(world.edgeNetworkId)
	world.listenAnswers = []func() (MailReceiverListener, error){
		func() (MailReceiverListener, error) { return world.listener, nil },
	}
	t.Cleanup(cancel)
	return world
}

// The receiver, made on first use with mutate's changes to its args.
func (self *mailReceiverTestWorld) newReceiver(mutate func(args *MailReceiverArgs)) *MailReceiver {
	self.t.Helper()
	args := &MailReceiverArgs{
		Host: "mx",
		Listen: func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error) {
			if address != "smtp/25/mx" || settings.MaxStreams != 16 || settings.Protocol != "smtp-starttls" {
				self.t.Errorf("listen on %q with %+v", address, settings)
			}
			answer := func() func() (MailReceiverListener, error) {
				self.listenLock.Lock()
				defer self.listenLock.Unlock()
				answer := self.listenAnswers[0]
				if 1 < len(self.listenAnswers) {
					self.listenAnswers = self.listenAnswers[1:]
				}
				return answer
			}()
			defer self.listenCalls.Update(func(count int) int { return count + 1 })
			return answer()
		},
		Keys:      self.keys,
		Publisher: self.publisher,
		Names: func(ctx context.Context) ([]string, error) {
			return slices.Clone(testMailReceiverNames), nil
		},
		Store: self.store,
		Serve: func(ctx context.Context, stream *MailReceiverStream) {
			self.streams <- stream
			stream.Tls.Close()
		},
		Clock: self.clock,
	}
	if mutate != nil {
		mutate(args)
	}
	receiver, err := NewMailReceiver(args)
	if err != nil {
		self.t.Fatal(err)
	}
	self.receiver = receiver
	return receiver
}

// The receiver started, its first listen's answer back.
func (self *mailReceiverTestWorld) start() error {
	if self.receiver == nil {
		self.newReceiver(nil)
	}
	return self.receiver.Start(self.ctx)
}

// Starts and waits until the current key serves, 2 TTLs after its TLSA went out.
func (self *mailReceiverTestWorld) startServing() {
	self.t.Helper()
	start := self.clock.Now()
	if err := self.start(); err != nil {
		self.t.Fatal(err)
	}
	self.clock.awaitWaitAt(start.Add(600 * time.Second))
	self.clock.Advance(600 * time.Second)
	self.listener.awaitServing(true)
}

// Hands the receiver a stream from dialerNetworkId and answers the leaf the handshake presented, or the client's
// error.
func (self *mailReceiverTestWorld) handshake(dialerNetworkId Id) (*x509.Certificate, error) {
	self.t.Helper()
	listenerEnd, senderEnd := newSocketStreamPipe(256 * 1024)
	ticket := &protocol.SocketTicket{DialerNetworkId: dialerNetworkId.Bytes(), Name: "smtp/25/mx"}
	self.listener.conns <- newSocketConn(listenerEnd, &SocketAddr{}, &SocketAddr{}, ticket, nil)
	sender := tls.Client(newSocketConn(senderEnd, &SocketAddr{}, &SocketAddr{}, nil, nil), &tls.Config{
		ServerName: testMailReceiverServerName,
		// a sender in opportunistic mode takes any certificate (§2.8 EX3); what it was shown is what is checked
		InsecureSkipVerify: true,
	})
	defer sender.Close()
	if err := sender.HandshakeContext(self.ctx); err != nil {
		return nil, err
	}
	certificates := sender.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return nil, errors.New("no certificate presented")
	}
	select {
	case stream := <-self.streams:
		if stream.SpkiSha256 != sha256.Sum256(certificates[0].RawSubjectPublicKeyInfo) {
			self.t.Errorf("the stream names another key than the one presented")
		}
	case <-self.ctx.Done():
		return nil, self.ctx.Err()
	}
	return certificates[0], nil
}

// The SHA-256 of a leaf's SPKI.
func testMailReceiverLeafSpki(leaf *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
}

// 2 TTLs: the key's TLSA goes out at once, serving stays false a second short of 600 s, and turns true at 600 s.
func TestMailReceiverServesOnlyTwoTtlsAfterItsTlsaGoesOut(t *testing.T) {
	world := newMailReceiverTestWorld(t, nil)
	start := world.clock.Now()
	if err := world.start(); err != nil {
		t.Fatal(err)
	}
	world.clock.awaitWaitAt(start.Add(600 * time.Second))
	publishes := world.publisher.publishes()
	current, _, _ := world.keys.TlsKeys()
	if len(publishes) != 1 || publishes[0].host != "mx" || publishes[0].spkiSha256 != current.SpkiSha256() {
		t.Fatalf("publishes %+v", publishes)
	}
	if serving, _ := world.listener.serving.Get(); serving {
		t.Fatal("serving before the key's TLSA was published 2 TTLs")
	}
	if _, _, err := world.receiver.certificate(); !errors.Is(err, ErrMailReceiverNotServing) {
		t.Fatalf("a certificate before the key is live: %v", err)
	}
	world.clock.Advance(599 * time.Second)
	if serving, _ := world.listener.serving.Get(); serving {
		t.Fatal("serving at 599 s")
	}
	world.clock.Advance(time.Second)
	world.listener.awaitServing(true)
	status := world.receiver.Status()
	if !status.Listening || !status.Serving || !bytes.Equal(status.SpkiSha256, publishes[0].spkiSha256[:]) {
		t.Fatalf("status %+v", status)
	}
	if len(world.publisher.publishes()) != 1 {
		t.Fatal("the key's TLSA went out twice")
	}
}

// Self-signed on the key until §13 issues, then the issued chain on the same key, every handshake answered.
func TestMailReceiverPresentsSelfSignedThenTheIssuedChainWithNoGap(t *testing.T) {
	world := newMailReceiverTestWorld(t, nil)
	world.startServing()
	current, _, _ := world.keys.TlsKeys()
	first, err := world.handshake(world.edgeNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.RawIssuer, first.RawSubject) || testMailReceiverLeafSpki(first) != current.SpkiSha256() {
		t.Fatal("the first handshake did not present a self-signed leaf on the device key")
	}
	if !slices.Equal(first.DNSNames, testMailReceiverNames) {
		t.Fatalf("names %v", first.DNSNames)
	}
	issued := world.keys.issue(t, current, testMailReceiverNames)
	second, err := world.handshake(world.edgeNetworkId)
	if err != nil {
		t.Fatalf("a gap at the chain's install: %v", err)
	}
	if !bytes.Equal(second.Raw, issued.Leaf.Raw) || testMailReceiverLeafSpki(second) != current.SpkiSha256() {
		t.Fatal("the issued chain did not follow the self-signed leaf")
	}
}

// A rotation: the successor's TLSA goes out as soon as it is pending, the old key serves on through the keychain's
// promotion, and the new key serves only once its TLSA is live.
func TestMailReceiverRotationKeepsTheOldKeyUntilTheNewTlsaIsLive(t *testing.T) {
	world := newMailReceiverTestWorld(t, nil)
	world.startServing()
	old, _, _ := world.keys.TlsKeys()
	next := world.keys.rotate(t)
	rotated := world.clock.Now()
	world.receiver.wakeKeys()
	world.publisher.awaitCount(2)
	world.clock.awaitWaitAt(rotated.Add(600 * time.Second))
	world.keys.promote()
	world.receiver.wakeKeys()
	world.clock.awaitWaitAt(rotated.Add(600 * time.Second))
	for range 2 {
		presented, err := world.handshake(world.edgeNetworkId)
		if err != nil {
			t.Fatal(err)
		}
		if testMailReceiverLeafSpki(presented) != old.SpkiSha256() {
			t.Fatal("the new key served before its TLSA was live")
		}
	}
	world.clock.Advance(599 * time.Second)
	presented, err := world.handshake(world.edgeNetworkId)
	if err != nil || testMailReceiverLeafSpki(presented) != old.SpkiSha256() {
		t.Fatalf("at 599 s the old key must still serve: %v", err)
	}
	world.clock.Advance(time.Second)
	for {
		status := world.receiver.Status()
		next := next.SpkiSha256()
		if bytes.Equal(status.SpkiSha256, next[:]) {
			break
		}
		world.clock.awaitWaitAt(world.clock.Now().Add(10 * time.Minute))
	}
	presented, err = world.handshake(world.edgeNetworkId)
	if err != nil || testMailReceiverLeafSpki(presented) != next.SpkiSha256() {
		t.Fatalf("the new key does not serve once live: %v", err)
	}
	publishes := world.publisher.publishes()
	if len(publishes) != 2 || publishes[0].spkiSha256 != old.SpkiSha256() || publishes[1].spkiSha256 != next.SpkiSha256() ||
		!publishes[1].at.Equal(rotated) {
		t.Fatalf("publishes %+v", publishes)
	}
}

// A restart after the keychain promoted a successor whose TLSA went out 100 s earlier serves nothing until it is
// live, and posts nothing again.
func TestMailReceiverRestartServesNothingBeforeTheNewKeyIsLive(t *testing.T) {
	store := newTestMemoryStore()
	world := newMailReceiverTestWorld(t, store)
	old, _, _ := world.keys.TlsKeys()
	next := world.keys.rotate(t)
	world.keys.promote()
	// what the run before the restart kept: the old key's TLSA long live, the new key's out 100 s ago
	records := newMailReceiverTlsaRecords(store, "mx")
	if err := records.put(old, world.clock.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	published := world.clock.Now().Add(-100 * time.Second)
	if err := records.put(next, published); err != nil {
		t.Fatal(err)
	}
	if err := world.start(); err != nil {
		t.Fatal(err)
	}
	world.clock.awaitWaitAt(published.Add(600 * time.Second))
	if serving, _ := world.listener.serving.Get(); serving {
		t.Fatal("a restart served the new key before its TLSA was live")
	}
	if 0 < len(world.publisher.publishes()) {
		t.Fatal("a restart posted a key whose TLSA it had recorded")
	}
	world.clock.Advance(499 * time.Second)
	if serving, _ := world.listener.serving.Get(); serving {
		t.Fatal("served a second early")
	}
	world.clock.Advance(time.Second)
	world.listener.awaitServing(true)
	presented, err := world.handshake(world.edgeNetworkId)
	if err != nil || testMailReceiverLeafSpki(presented) != next.SpkiSha256() {
		t.Fatalf("the new key once live: %v", err)
	}
	// the old key's record goes once nothing holds or serves it
	reloaded := newMailReceiverTlsaRecords(store, "mx")
	if err := reloaded.load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.publishTime(old); ok {
		t.Fatal("the rotated-out key's record was kept")
	}
	if at, ok := reloaded.publishTime(next); !ok || !at.Equal(published) {
		t.Fatal("the new key's record moved")
	}
}

// A listen waiting on a person surfaces its approval, and the receiver asks again until the decision lets it through.
func TestMailReceiverListenWaitingOnApprovalStartsOnceApproved(t *testing.T) {
	world := newMailReceiverTestWorld(t, nil)
	approvalId := NewId()
	world.listenAnswers = []func() (MailReceiverListener, error){
		func() (MailReceiverListener, error) { return nil, &ApprovalPendingError{ApprovalId: approvalId} },
		func() (MailReceiverListener, error) { return world.listener, nil },
	}
	start := world.clock.Now()
	err := world.start()
	pending := &ApprovalPendingError{}
	if !errors.As(err, &pending) || pending.ApprovalId != approvalId {
		t.Fatalf("Start answered %v", err)
	}
	status := world.receiver.Status()
	if status.Listening || status.ApprovalId == nil || *status.ApprovalId != approvalId {
		t.Fatalf("status %+v", status)
	}
	world.clock.awaitWaitAt(start.Add(time.Minute))
	if 0 < len(world.publisher.publishes()) {
		t.Fatal("a key went out before the listen")
	}
	world.clock.Advance(time.Minute)
	world.publisher.awaitCount(1)
	world.clock.awaitWaitAt(start.Add(time.Minute + 600*time.Second))
	status = world.receiver.Status()
	if !status.Listening || status.ApprovalId != nil {
		t.Fatalf("status once approved %+v", status)
	}
	world.clock.Advance(600 * time.Second)
	world.listener.awaitServing(true)
}

// The listen's end, as a revocation ends it, stops the receiver at once, and the next listen goes through the gate,
// which a revoked grant refuses.
func TestMailReceiverStopsAtOnceWhenItsListenEnds(t *testing.T) {
	world := newMailReceiverTestWorld(t, nil)
	world.startServing()
	world.listenAnswers = []func() (MailReceiverListener, error){
		func() (MailReceiverListener, error) { return nil, ErrSidecarGateDenied },
	}
	ended := world.clock.Now()
	world.listener.Close()
	world.clock.awaitWaitAt(ended.Add(30 * time.Second))
	status := world.receiver.Status()
	if status.Listening || status.Serving {
		t.Fatalf("status after the listen ended %+v", status)
	}
	if _, _, err := world.receiver.certificate(); !errors.Is(err, ErrMailReceiverNotServing) {
		t.Fatalf("a certificate after the listen ended: %v", err)
	}
	world.clock.Advance(30 * time.Second)
	world.clock.awaitWaitAt(ended.Add(60 * time.Second))
	if calls, _ := world.listenCalls.Get(); calls != 2 {
		t.Fatalf("%d listens", calls)
	}
	if status := world.receiver.Status(); status.Listening || !strings.Contains(status.Problem, "listen") {
		t.Fatalf("status after the gate refused %+v", status)
	}
}

// A stream whose ticket is not the edge's is reset before a byte of TLS, and reaches no session.
func TestMailReceiverResetsAStreamNotFromTheEdge(t *testing.T) {
	world := newMailReceiverTestWorld(t, nil)
	world.startServing()
	if _, err := world.handshake(NewId()); err == nil {
		t.Fatal("a stream from another network was served")
	}
	select {
	case <-world.streams:
		t.Fatal("a stream from another network reached the session")
	default:
	}
	if _, err := world.handshake(world.edgeNetworkId); err != nil {
		t.Fatalf("the edge's stream after a refusal: %v", err)
	}
}

// A failed POST /dns/key-record serves nothing and is tried again after PublishRetryInterval.
func TestMailReceiverRetriesAFailedKeyRecord(t *testing.T) {
	world := newMailReceiverTestWorld(t, nil)
	world.publisher.err = errors.New("synthetic dns block refusal")
	start := world.clock.Now()
	if err := world.start(); err != nil {
		t.Fatal(err)
	}
	world.clock.awaitWaitAt(start.Add(30 * time.Second))
	if status := world.receiver.Status(); status.Serving || !strings.Contains(status.Problem, "key record") {
		t.Fatalf("status %+v", status)
	}
	func() {
		world.publisher.stateLock.Lock()
		defer world.publisher.stateLock.Unlock()
		world.publisher.err = nil
	}()
	world.clock.Advance(30 * time.Second)
	world.clock.awaitWaitAt(start.Add(30*time.Second + 600*time.Second))
	world.clock.Advance(600 * time.Second)
	world.listener.awaitServing(true)
}

// The capture of one POST /dns/key-record.
type mailReceiverTestDnsBlock struct {
	stateLock sync.Mutex
	paths     []string
	bodies    [][]byte
}

func (self *mailReceiverTestDnsBlock) RoundTrip(request *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(request.Body)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.paths = append(self.paths, request.Method+" "+request.URL.Path)
	self.bodies = append(self.bodies, body)
	answer, _ := json.Marshal(&DnsKeyRecordAnswer{Version: 7})
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(answer)), Request: request}, nil
}

// POST /dns/key-record's body names the key's SPKI and an attestation the identity key signed for that key and the
// network's set, and neither it nor the receiver's store holds a byte of the private key.
func TestMailReceiverKeyRecordCarriesOnlyTheSpkiAndItsAttestation(t *testing.T) {
	clock := newMailReceiverTestClock()
	networkId, sidecarId := NewId(), NewId()
	seed := bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)
	identityPublicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	block := &mailReceiverTestDnsBlock{}
	dns, err := NewDnsClient(&DnsClientArgs{
		DnsUrl:    "https://dns.test.example",
		Transport: block,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return "synthetic-dns-token", nil
		},
		NetworkId: networkId,
		Clock:     clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Close)
	publisher := newMailReceiverDnsPublisher(dns, testTlsSign(seed, sidecarId[:]), networkId, sidecarId, clock)
	world := newMailReceiverTestWorld(t, nil)
	world.newReceiver(func(args *MailReceiverArgs) {
		args.Publisher = publisher
	})
	world.startServing()
	if _, err := world.handshake(world.edgeNetworkId); err != nil {
		t.Fatal(err)
	}

	current, _, _ := world.keys.TlsKeys()
	scalar := current.privateKey.D.FillBytes(make([]byte, tlsDeviceKeyScalarSize))
	block.stateLock.Lock()
	defer block.stateLock.Unlock()
	if len(block.paths) != 1 || block.paths[0] != "POST "+DnsKeyRecordPath {
		t.Fatalf("requests %v", block.paths)
	}
	request := &DnsKeyRecordRequest{}
	if err := json.Unmarshal(block.bodies[0], request); err != nil {
		t.Fatal(err)
	}
	identifierSetSha256, err := TlsIdentifierSetHash(testMailReceiverNames)
	if err != nil {
		t.Fatal(err)
	}
	if request.Host != "mx" || !bytes.Equal(request.Spki, current.Spki()) {
		t.Fatalf("request host %q", request.Host)
	}
	if _, err := VerifyTlsKeyAttestation(request.Attestation, identityPublicKey, networkId, sidecarId, current.SpkiSha256(), identifierSetSha256); err != nil {
		t.Fatalf("the attestation does not verify: %v", err)
	}
	if bytes.Contains(block.bodies[0], scalar) {
		t.Fatal("the request holds the private key")
	}
	world.store.shared.stateLock.Lock()
	defer world.store.shared.stateLock.Unlock()
	if len(world.store.shared.files) == 0 {
		t.Fatal("no tlsa record was kept")
	}
	for name, content := range world.store.shared.files {
		if bytes.Contains(content, scalar) || bytes.Contains(content, current.Spki()) {
			t.Fatalf("%s holds key material beyond the SPKI's hash", name)
		}
	}
}
