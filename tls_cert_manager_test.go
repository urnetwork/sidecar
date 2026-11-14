//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"go/parser"
	"go/token"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A clock a test moves by hand, whose timers fire only as it is advanced past them, so nothing here waits on real
// time. A test learns that a goroutine has parked on a timer by awaiting the timer's own instant.
type tlsCertTestClock struct {
	stateLock sync.Mutex
	current   time.Time
	timers    []*tlsCertTestTimer
	// closed and replaced whenever a timer is added
	added chan struct{}
}

type tlsCertTestTimer struct {
	at   time.Time
	fire func(at time.Time)
}

func newTlsCertTestClock() *tlsCertTestClock {
	return &tlsCertTestClock{
		current: time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC),
		added:   make(chan struct{}),
	}
}

func (self *tlsCertTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

func (self *tlsCertTestClock) addTimer(timeout time.Duration, fire func(at time.Time)) *tlsCertTestTimer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	timer := &tlsCertTestTimer{at: self.current.Add(timeout), fire: fire}
	self.timers = append(self.timers, timer)
	close(self.added)
	self.added = make(chan struct{})
	return timer
}

func (self *tlsCertTestClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	self.addTimer(timeout, func(at time.Time) {
		fired <- at
	})
	return fired
}

func (self *tlsCertTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	timer := self.addTimer(timeout, func(at time.Time) {
		go function()
	})
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		before := len(self.timers)
		self.timers = slices.DeleteFunc(self.timers, func(other *tlsCertTestTimer) bool {
			return other == timer
		})
		return len(self.timers) < before
	}
}

// Moves the clock and fires every timer it passed, in time order.
func (self *tlsCertTestClock) advance(by time.Duration) {
	due := func() []*tlsCertTestTimer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.current = self.current.Add(by)
		due := []*tlsCertTestTimer{}
		self.timers = slices.DeleteFunc(self.timers, func(timer *tlsCertTestTimer) bool {
			if timer.at.After(self.current) {
				return false
			}
			due = append(due, timer)
			return true
		})
		return due
	}()
	slices.SortStableFunc(due, func(a *tlsCertTestTimer, b *tlsCertTestTimer) int {
		return a.at.Compare(b.at)
	})
	for _, timer := range due {
		timer.fire(timer.at)
	}
}

// Waits until some goroutine has a timer set for exactly timeout from now.
func (self *tlsCertTestClock) awaitTimer(t *testing.T, timeout time.Duration) {
	t.Helper()
	// a guard against a broken test, never the proof
	guard := time.After(30 * time.Second)
	for {
		found, added := func() (bool, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			at := self.current.Add(timeout)
			return slices.ContainsFunc(self.timers, func(timer *tlsCertTestTimer) bool {
				return timer.at.Equal(at)
			}), self.added
		}()
		if found {
			return
		}
		select {
		case <-added:
		case <-guard:
			t.Fatalf("no timer for %s was set", timeout)
		}
	}
}

// A test CA and the certs proxy's rows behind TlsCertApi.
type tlsCertTestApi struct {
	t         *testing.T
	clock     *tlsCertTestClock
	networkId Id
	sidecarId Id
	root      string
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate

	stateLock sync.Mutex
	rows      []*TlsCertRecord
	// every order's body, in order
	orders       []*TlsCertOrderArgs
	orderTokens  []string
	certsCount   int
	statusCount  int
	revokes      []*TlsCertRevokeArgs
	retryAfterMs uint32
	orderErr     error
	serialSeq    int64
	// when set, each GET /tls/certs reports here and waits for a release
	certsEntered chan struct{}
	certsRelease chan struct{}
}

func newTlsCertTestApi(t *testing.T, clock *tlsCertTestClock, networkId Id, sidecarId Id, root string) *tlsCertTestApi {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tls test ca"},
		NotBefore:             clock.Now().Add(-time.Hour),
		NotAfter:              clock.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsCertTestApi{t: t, clock: clock, networkId: networkId, sidecarId: sidecarId, root: root, caKey: caKey, caCert: caCert}
}

func (self *tlsCertTestApi) TlsCertOrder(ctx context.Context, serviceToken string, args *TlsCertOrderArgs) (*TlsCertOrderResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.orderErr != nil {
		return nil, self.orderErr
	}
	csr, err := x509.ParseCertificateRequest(args.Csr)
	if err != nil || csr.CheckSignature() != nil {
		return nil, &SidecarApiError{Route: tlsCertOrderRoute, Status: 400}
	}
	identifierSetSha256, err := TlsIdentifierSetHash(csr.DNSNames)
	if err != nil {
		return nil, &SidecarApiError{Route: tlsCertOrderRoute, Status: 400}
	}
	spkiSha256 := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	state := TlsCertStateQueued
	if len(csr.DNSNames) == 1 && !strings.HasSuffix(csr.DNSNames[0], "."+self.root) {
		state = TlsCertStateCustomQueued
	}
	self.orders = append(self.orders, args)
	self.orderTokens = append(self.orderTokens, serviceToken)
	row := &TlsCertRecord{
		CertId:              NewId(),
		NetworkId:           self.networkId,
		SidecarId:           self.sidecarId,
		IdentifierSetSha256: identifierSetSha256[:],
		SpkiSha256:          spkiSha256[:],
		Attestation:         args.Attestation,
		Csr:                 args.Csr,
		State:               state,
		StateTime:           self.clock.Now(),
	}
	self.rows = append(self.rows, row)
	return &TlsCertOrderResult{CertId: row.CertId, State: row.State, RetryAfterMs: self.retryAfterMs}, nil
}

func (self *tlsCertTestApi) TlsCertOrderStatus(ctx context.Context, serviceToken string, certId Id) (*TlsCertOrderStatus, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.statusCount += 1
	for _, row := range self.rows {
		if row.CertId == certId {
			return &TlsCertOrderStatus{State: row.State, RetryAfterMs: self.retryAfterMs, Chain: row.Chain}, nil
		}
	}
	return nil, &SidecarApiError{Route: tlsCertOrderStatusRoute, Status: 404}
}

func (self *tlsCertTestApi) TlsCerts(ctx context.Context) (*TlsCertsResult, error) {
	entered, release := func() (chan struct{}, chan struct{}) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.certsCount += 1
		return self.certsEntered, self.certsRelease
	}()
	if entered != nil {
		entered <- struct{}{}
		<-release
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	result := &TlsCertsResult{Certs: []*TlsCertRecord{}}
	for _, row := range self.rows {
		copied := *row
		result.Certs = append(result.Certs, &copied)
	}
	return result, nil
}

func (self *tlsCertTestApi) TlsCertRevoke(ctx context.Context, args *TlsCertRevokeArgs) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revokes = append(self.revokes, args)
	for _, row := range self.rows {
		if row.CertId == args.CertId {
			row.State = TlsCertStateRevoking
		}
	}
	return nil
}

// A chain for csrDer's key and names, valid for lifetime from now, signed by the test CA.
func (self *tlsCertTestApi) chainFor(csrDer []byte, names []string, lifetime time.Duration) [][]byte {
	self.t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		self.t.Fatal(err)
	}
	if names == nil {
		names = csr.DNSNames
	}
	self.serialSeq += 1
	template := &x509.Certificate{
		// a high bit set, so the ARI id's serial needs its leading zero octet
		SerialNumber: big.NewInt(0x80000000 + self.serialSeq),
		NotBefore:    self.clock.Now().Add(-time.Minute + time.Duration(self.serialSeq)*time.Second),
		NotAfter:     self.clock.Now().Add(lifetime),
		DNSNames:     names,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, self.caCert, csr.PublicKey, self.caKey)
	if err != nil {
		self.t.Fatal(err)
	}
	return [][]byte{der, self.caCert.Raw}
}

// Issues row certId as certs or an ordering desktop would.
func (self *tlsCertTestApi) issue(certId Id, lifetime time.Duration) {
	self.t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, row := range self.rows {
		if row.CertId != certId {
			continue
		}
		row.Chain = self.chainFor(row.Csr, nil, lifetime)
		if row.State.CustomOpen() {
			row.State = TlsCertStateCustomIssued
		} else {
			row.State = TlsCertStateIssued
		}
		return
	}
	self.t.Fatalf("no row to issue")
}

func (self *tlsCertTestApi) setState(certId Id, state TlsCertState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, row := range self.rows {
		if row.CertId == certId {
			row.State = state
		}
	}
}

func (self *tlsCertTestApi) removeRow(certId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rows = slices.DeleteFunc(self.rows, func(row *TlsCertRecord) bool {
		return row.CertId == certId
	})
}

func (self *tlsCertTestApi) addRow(row *TlsCertRecord) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rows = append(self.rows, row)
}

func (self *tlsCertTestApi) orderCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.orders)
}

func (self *tlsCertTestApi) lastOrder() *TlsCertOrderArgs {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.orders[len(self.orders)-1]
}

func (self *tlsCertTestApi) lastRow() *TlsCertRecord {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *self.rows[len(self.rows)-1]
	return &copied
}

func (self *tlsCertTestApi) certsReads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.certsCount
}

// The device key through a tlsDeviceState, as a Sidecar reaches it.
type tlsCertTestKeys struct {
	state   *tlsDeviceState
	secrets SidecarSecrets
	clock   Clock
}

func (self *tlsCertTestKeys) TlsKeys() (*TlsDeviceKey, *TlsDeviceKey, error) {
	keys, err := self.state.keys(self.secrets, self.clock.Now())
	if err != nil {
		return nil, nil, err
	}
	return keys.current, keys.pending, nil
}

func (self *tlsCertTestKeys) RotateTlsKey(reason TlsKeyRotationReason) (*TlsDeviceKey, error) {
	keys, err := self.state.rotate(self.secrets, self.clock.Now(), reason)
	if err != nil {
		return nil, err
	}
	return keys.pending, nil
}

func (self *tlsCertTestKeys) PromoteTlsKey(spkiSha256 [sha256.Size]byte) error {
	_, err := self.state.promote(self.secrets, spkiSha256)
	return err
}

const (
	tlsCertTestRoot   = "sidecar.example"
	tlsCertTestLabel  = "abcdefghij"
	tlsCertTestCustom = "app.customer.example"
	// LE's tlsserver profile
	tlsCertTestLifetime = 45 * 24 * time.Hour
)

// A manager on a real keychain and sealed store, a test CA behind its api, and a clock the test moves.
type tlsCertFixture struct {
	t         *testing.T
	clock     *tlsCertTestClock
	api       *tlsCertTestApi
	manager   *TlsCertManager
	settings  *SidecarTlsSettings
	keys      *tlsCertTestKeys
	store     SidecarStore
	networkId Id
	sidecarId Id
	identity  []byte

	stateLock   sync.Mutex
	customHosts []string
	namesErr    error
}

func newTlsCertFixture(t *testing.T) *tlsCertFixture {
	t.Helper()
	instance, _, _, secrets := newTlsTestSecrets(t)
	clock := newTlsCertTestClock()
	settings := DefaultSidecarTlsSettings()
	settings.CertsResource = "https://certs.example"
	store, err := instance.Store(&testNetworkId).Directory(tlsComponentName, tlsComponentName)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("tls cert manager test identity"))
	sidecarId := tlsCertTestId("tls cert manager test sidecar")
	fixture := &tlsCertFixture{
		t:         t,
		clock:     clock,
		settings:  settings,
		keys:      &tlsCertTestKeys{state: newTlsDeviceState(settings), secrets: secrets, clock: clock},
		store:     store,
		networkId: testNetworkId,
		sidecarId: sidecarId,
		identity:  seed[:],
	}
	fixture.api = newTlsCertTestApi(t, clock, testNetworkId, sidecarId, tlsCertTestRoot)
	fixture.manager = fixture.newManager()
	return fixture
}

func (self *tlsCertFixture) names(ctx context.Context) (*TlsCertNames, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.namesErr != nil {
		return nil, self.namesErr
	}
	return &TlsCertNames{Root: tlsCertTestRoot, Label: tlsCertTestLabel, CustomHosts: slices.Clone(self.customHosts)}, nil
}

func (self *tlsCertFixture) setCustomHosts(hosts ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.customHosts = hosts
}

// A manager over the fixture's keychain and store, as a restart makes one, attached to no api.
func (self *tlsCertFixture) newManager() *TlsCertManager {
	self.t.Helper()
	manager, err := NewTlsCertManager(self.t.Context(), &TlsCertManagerArgs{
		NetworkId: self.networkId,
		SidecarId: self.sidecarId,
		Settings:  self.settings,
		Keys:      self.keys,
		Sign:      testTlsSign(self.identity, self.sidecarId[:]),
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return "service token for " + resource, nil
		},
		Names: self.names,
		Store: self.store,
		Clock: self.clock,
		Log:   NewNoopLogger(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(manager.Close)
	return manager
}

func (self *tlsCertFixture) sync() error {
	return self.manager.Sync(self.t.Context())
}

func (self *tlsCertFixture) mustSync() {
	self.t.Helper()
	if err := self.sync(); err != nil {
		self.t.Fatalf("sync: %v", err)
	}
}

func (self *tlsCertFixture) networkSet() []string {
	return []string{"*." + tlsCertTestLabel + "." + tlsCertTestRoot, tlsCertTestLabel + "." + tlsCertTestRoot}
}

// Orders and installs the network's certificate through EnsureTlsCertificate, on an api that issues at once.
func (self *tlsCertFixture) ensureIssued() *tls.Certificate {
	self.t.Helper()
	type outcome struct {
		certificate *tls.Certificate
		err         error
	}
	done := make(chan outcome, 1)
	go func() {
		certificate, err := self.manager.EnsureTlsCertificate(self.t.Context())
		done <- outcome{certificate: certificate, err: err}
	}()
	// the order is placed and its first status read answers queued: the poll parks on its timer
	self.clock.awaitTimer(self.t, self.settings.CertOrderPollInterval)
	self.api.issue(self.api.lastRow().CertId, tlsCertTestLifetime)
	self.clock.advance(self.settings.CertOrderPollInterval)
	result := <-done
	if result.err != nil {
		self.t.Fatalf("ensure: %v", result.err)
	}
	return result.certificate
}

// A fixture attached to its api with nothing running in the background: the manager's own loop stays parked on its
// resync timer, and the test drives each pass by hand.
func newAttachedTlsCertFixture(t *testing.T) *tlsCertFixture {
	t.Helper()
	fixture := newTlsCertFixture(t)
	fixture.attach()
	return fixture
}

// Attaches the api and waits out the pass the attachment asks for, until the loop is parked on its resync timer.
func (self *tlsCertFixture) attach() {
	self.t.Helper()
	self.manager.SetApi(self.api)
	self.settleLoop()
}

// Waits for the loop's pass to end and for the loop to park on its resync timer.
func (self *tlsCertFixture) settleLoop() {
	self.t.Helper()
	self.clock.awaitTimer(self.t, self.settings.CertHintMinInterval)
	self.clock.advance(self.settings.CertHintMinInterval)
	self.clock.awaitTimer(self.t, self.settings.CertResyncInterval)
}

func tlsCertLeafOf(t *testing.T, certificate *tls.Certificate) *x509.Certificate {
	t.Helper()
	if certificate == nil || certificate.Leaf == nil {
		t.Fatal("no certificate")
	}
	return certificate.Leaf
}

func TestTlsCertManagerOrdersPollsAndServesAcrossARestart(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.api.retryAfterMs = 7000

	type outcome struct {
		certificate *tls.Certificate
		err         error
	}
	done := make(chan outcome, 1)
	go func() {
		certificate, err := fixture.manager.EnsureTlsCertificate(t.Context())
		done <- outcome{certificate: certificate, err: err}
	}()
	// the server's retry_after is the wait, not the default
	fixture.clock.awaitTimer(t, 7*time.Second)
	if fixture.api.orderCount() != 1 {
		t.Fatalf("%d orders", fixture.api.orderCount())
	}
	order := fixture.api.lastOrder()
	if order.Replaces != "" {
		t.Errorf("a first order names a predecessor %q", order.Replaces)
	}
	if token := fixture.api.orderTokens[0]; token != "service token for https://certs.example" {
		t.Errorf("the order's token %q", token)
	}
	// the CSR is on the device key, for exactly the device's set, and the attestation binds both
	csr, err := x509.ParseCertificateRequest(order.Csr)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := fixture.keys.TlsKeys()
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(csr.RawSubjectPublicKeyInfo) != current.SpkiSha256() {
		t.Errorf("the csr is on another key")
	}
	if !slices.Equal(csr.DNSNames, fixture.networkSet()) {
		t.Errorf("the csr names %v", csr.DNSNames)
	}
	setSha256, err := TlsIdentifierSetHash(fixture.networkSet())
	if err != nil {
		t.Fatal(err)
	}
	identityPublicKey := testTlsIdentityPublicKey(fixture.identity)
	if _, err := VerifyTlsKeyAttestation(order.Attestation, identityPublicKey, fixture.networkId, fixture.sidecarId, current.SpkiSha256(), setSha256); err != nil {
		t.Errorf("the attestation: %v", err)
	}

	// still queued after the wait: asked again, and no second order
	fixture.clock.advance(7 * time.Second)
	fixture.clock.awaitTimer(t, 7*time.Second)
	select {
	case result := <-done:
		t.Fatalf("ensure returned before the order issued: %v", result.err)
	default:
	}
	fixture.api.issue(fixture.api.lastRow().CertId, tlsCertTestLifetime)
	fixture.clock.advance(7 * time.Second)
	result := <-done
	if result.err != nil {
		t.Fatalf("ensure: %v", result.err)
	}
	leaf := tlsCertLeafOf(t, result.certificate)
	if !slices.Equal(slices.Sorted(slices.Values(leaf.DNSNames)), fixture.networkSet()) {
		t.Errorf("leaf names %v", leaf.DNSNames)
	}
	if !tlsCertOnKey(result.certificate, current) {
		t.Errorf("the certificate is not on the device key")
	}
	if fixture.api.orderCount() != 1 {
		t.Errorf("%d orders for one certificate", fixture.api.orderCount())
	}
	// a second ask answers the installed chain and orders nothing
	again, err := fixture.manager.EnsureTlsCertificate(t.Context())
	if err != nil || !bytes.Equal(again.Certificate[0], result.certificate.Certificate[0]) || fixture.api.orderCount() != 1 {
		t.Errorf("a second ensure: %v, %d orders", err, fixture.api.orderCount())
	}
	// one host of the wildcard is covered, another zone's is not
	now := fixture.clock.Now()
	if fixture.manager.IssuedTlsCertificate([]string{"blog." + tlsCertTestLabel + "." + tlsCertTestRoot}, now) == nil {
		t.Errorf("a one-label host is not covered")
	}
	if fixture.manager.IssuedTlsCertificate([]string{"blog.other." + tlsCertTestRoot}, now) != nil {
		t.Errorf("another zone's host is covered")
	}
	if fixture.manager.IssuedTlsCertificate([]string{"192.0.2.1"}, now) != nil {
		t.Errorf("an address is covered")
	}

	// a restart reads the chain back from the store and serves it with no api at all
	restarted := fixture.newManager()
	served := restarted.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now())
	if served == nil || !bytes.Equal(served.Certificate[0], result.certificate.Certificate[0]) {
		t.Fatalf("the chain did not survive a restart")
	}
	if infos := restarted.Certificates(); len(infos) != 1 || !infos[0].Presented || infos[0].State != TlsCertStateIssued {
		t.Errorf("certificates after a restart %+v", infos)
	}
}

// Whether certificate's leaf and its signer are both key.
func tlsCertOnKey(certificate *tls.Certificate, key *TlsDeviceKey) bool {
	signer, ok := certificate.PrivateKey.(*TlsDeviceKey)
	return ok && signer.SpkiSha256() == key.SpkiSha256() && sha256.Sum256(certificate.Leaf.RawSubjectPublicKeyInfo) == key.SpkiSha256()
}

// An id made from a label, the same each run.
func tlsCertTestId(label string) Id {
	sum := sha256.Sum256([]byte(label))
	return Id(sum[:16])
}

// The identity public key testTlsSign's seed signs under.
func testTlsIdentityPublicKey(seed []byte) []byte {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func TestTlsCertManagerAHintFetchesOnce(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	attachedReads := fixture.api.certsReads()

	entered := make(chan struct{})
	release := make(chan struct{})
	func() {
		fixture.api.stateLock.Lock()
		defer fixture.api.stateLock.Unlock()
		fixture.api.certsEntered = entered
		fixture.api.certsRelease = release
	}()

	fixture.manager.Hint(PushNotice{Topic: PushTopicTls})
	<-entered
	// a burst while the read is out costs one more read, not three
	fixture.manager.Hint(PushNotice{Topic: PushTopicTls})
	fixture.manager.Hint(PushNotice{Topic: PushTopicTls})
	fixture.manager.Hint(PushNotice{Topic: PushTopicTls, Resync: true})
	release <- struct{}{}
	fixture.clock.awaitTimer(t, fixture.settings.CertHintMinInterval)
	fixture.clock.advance(fixture.settings.CertHintMinInterval)
	<-entered
	release <- struct{}{}
	fixture.settleLoop()
	if reads := fixture.api.certsReads() - attachedReads; reads != 2 {
		t.Errorf("%d reads for one hint and one burst", reads)
	}
}

func TestTlsCertManagerResyncsHourlyAfterALostHint(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	certificate := fixture.ensureIssued()
	certId := fixture.api.lastRow().CertId
	before := fixture.api.certsReads()

	// the revocation's hint is lost: nothing reads until the hour
	fixture.api.setState(certId, TlsCertStateRevoked)
	if fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now()) == nil {
		t.Fatalf("the certificate stopped serving with no read")
	}
	fixture.clock.advance(fixture.settings.CertResyncInterval)
	fixture.settleLoop()
	if reads := fixture.api.certsReads() - before; reads != 1 {
		t.Errorf("%d reads at the hour", reads)
	}
	if served := fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now()); served != nil {
		t.Errorf("a revoked certificate still serves after the resync: %x", certificate.Certificate[0][:8])
	}
}

func TestTlsCertManagerRotationSwapsWithNoGap(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	old := fixture.ensureIssued()
	oldLeaf := tlsCertLeafOf(t, old)
	oldKey, _, err := fixture.keys.TlsKeys()
	if err != nil {
		t.Fatal(err)
	}

	if err := fixture.manager.RotateTlsKey(t.Context(), TlsKeyRotationRequest); err != nil {
		t.Fatal(err)
	}
	fixture.settleLoop()
	// the successor is ordered on the pending key, naming the old certificate, and the old one still serves
	if fixture.api.orderCount() != 2 {
		t.Fatalf("%d orders after a rotation", fixture.api.orderCount())
	}
	order := fixture.api.lastOrder()
	if want := tlsAriCertificateId(oldLeaf); want == "" || order.Replaces != want {
		t.Errorf("replaces %q, want %q", order.Replaces, want)
	}
	_, pending, err := fixture.keys.TlsKeys()
	if err != nil || pending == nil {
		t.Fatalf("no pending key: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(order.Csr)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(csr.RawSubjectPublicKeyInfo) != pending.SpkiSha256() {
		t.Errorf("the successor's csr is not on the pending key")
	}
	served := fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now())
	if served == nil || !bytes.Equal(served.Certificate[0], old.Certificate[0]) || !tlsCertOnKey(served, oldKey) {
		t.Fatalf("the old certificate stopped serving before its successor arrived")
	}
	// a second pass places no second order
	fixture.mustSync()
	if fixture.api.orderCount() != 2 {
		t.Errorf("%d orders after a second pass", fixture.api.orderCount())
	}

	// the chain arrives: the same pass installs it and promotes the key
	fixture.api.issue(fixture.api.lastRow().CertId, tlsCertTestLifetime)
	fixture.mustSync()
	current, pendingAfter, err := fixture.keys.TlsKeys()
	if err != nil {
		t.Fatal(err)
	}
	if pendingAfter != nil || current.SpkiSha256() != pending.SpkiSha256() {
		t.Fatalf("the pending key was not promoted")
	}
	swapped := fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now())
	if swapped == nil || bytes.Equal(swapped.Certificate[0], old.Certificate[0]) {
		t.Fatalf("the successor does not serve after its install")
	}
	if sha256.Sum256(swapped.Leaf.RawSubjectPublicKeyInfo) != pending.SpkiSha256() {
		t.Errorf("the serving certificate is not on the promoted key")
	}
	// the old key is gone, and its chain with it
	if infos := fixture.manager.Certificates(); len(infos) != 1 {
		t.Errorf("%d certificates after the swap", len(infos))
	}
	// a request's rotation revokes nothing: the predecessor lapses
	if len(fixture.api.revokes) != 0 {
		t.Errorf("a requested rotation revoked %d certificates", len(fixture.api.revokes))
	}
}

func TestTlsCertManagerSuspicionRevokesThePredecessorOnceTheSuccessorServes(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	oldCertId := fixture.api.lastRow().CertId
	if err := fixture.manager.RotateTlsKey(t.Context(), TlsKeyRotationSuspicion); err != nil {
		t.Fatal(err)
	}
	fixture.settleLoop()
	if len(fixture.api.revokes) != 0 {
		t.Fatalf("the predecessor was revoked before its successor served")
	}
	fixture.api.issue(fixture.api.lastRow().CertId, tlsCertTestLifetime)
	fixture.mustSync()
	// owed at the swap, sent at the next pass
	fixture.mustSync()
	if len(fixture.api.revokes) != 1 || fixture.api.revokes[0].CertId != oldCertId || !fixture.api.revokes[0].KeyCompromise {
		t.Fatalf("revocations %+v", fixture.api.revokes)
	}
	fixture.mustSync()
	if len(fixture.api.revokes) != 1 {
		t.Errorf("the revocation was sent %d times", len(fixture.api.revokes))
	}
}

func TestTlsCertManagerScheduledRotationAt180Days(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	// a renewal's chain, long enough to be live when the key comes due
	renewal := fixture.api.lastRow()
	renewal.CertId = NewId()
	renewal.Chain = fixture.api.chainFor(renewal.Csr, nil, 400*24*time.Hour)
	fixture.api.addRow(renewal)
	fixture.mustSync()

	fixture.clock.advance(fixture.settings.KeyRotationInterval - 2*time.Hour)
	fixture.mustSync()
	if _, pending, _ := fixture.keys.TlsKeys(); pending != nil || fixture.api.orderCount() != 1 {
		t.Fatalf("a key rotated before it was due")
	}
	fixture.clock.advance(2 * time.Hour)
	fixture.mustSync()
	_, pending, err := fixture.keys.TlsKeys()
	if err != nil || pending == nil || pending.Reason() != TlsKeyRotationScheduled {
		t.Fatalf("no scheduled successor at 180 days: %v", err)
	}
	if fixture.api.orderCount() != 2 || fixture.api.lastOrder().Replaces == "" {
		t.Errorf("%d orders, replaces %q", fixture.api.orderCount(), fixture.api.lastOrder().Replaces)
	}
}

func TestTlsCertManagerReordersALostRowWithReplaces(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	certificate := fixture.ensureIssued()
	leaf := tlsCertLeafOf(t, certificate)
	fixture.mustSync()
	if fixture.api.orderCount() != 1 {
		t.Fatalf("%d orders with the row in place", fixture.api.orderCount())
	}

	// a restore behind the row: the local chain is live and no row names it
	fixture.api.removeRow(fixture.api.lastRow().CertId)
	fixture.mustSync()
	if fixture.api.orderCount() != 2 {
		t.Fatalf("%d orders after the row was lost", fixture.api.orderCount())
	}
	if want := tlsAriCertificateId(leaf); fixture.api.lastOrder().Replaces != want {
		t.Errorf("replaces %q, want %q", fixture.api.lastOrder().Replaces, want)
	}
	// the chain keeps serving local services meanwhile, and a second pass orders nothing more
	if fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now()) == nil {
		t.Errorf("the live chain stopped serving")
	}
	fixture.mustSync()
	if fixture.api.orderCount() != 2 {
		t.Errorf("%d orders after a second pass", fixture.api.orderCount())
	}
	fixture.api.issue(fixture.api.lastRow().CertId, tlsCertTestLifetime)
	fixture.mustSync()
	fixture.mustSync()
	if fixture.api.orderCount() != 2 {
		t.Errorf("%d orders once the new row issued", fixture.api.orderCount())
	}
	served := fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now())
	if served == nil || bytes.Equal(served.Certificate[0], certificate.Certificate[0]) {
		t.Errorf("the re-ordered chain does not serve")
	}
}

func TestTlsCertManagerARevokedCertificateStopsServingAtOnce(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	certId := fixture.api.lastRow().CertId

	for _, state := range []TlsCertState{TlsCertStateRevoking, TlsCertStateRevoked, TlsCertState("a_state_from_later")} {
		fixture.api.setState(certId, TlsCertStateIssued)
		fixture.mustSync()
		if fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now()) == nil {
			t.Fatalf("an issued certificate does not serve")
		}
		fixture.api.setState(certId, state)
		fixture.mustSync()
		// local services fall back to the self-signed leaf, which a nil answer selects, on the same key
		if fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now()) != nil {
			t.Errorf("a certificate whose row reads %s still serves", state)
		}
		// publishing gets no certificate at all
		if _, err := fixture.manager.PublishCertificate(fixture.networkSet()); !errors.Is(err, ErrTlsNoIssuedCertificate) {
			t.Errorf("publishing with a row that reads %s: %v", state, err)
		}
	}
	current, _, err := fixture.keys.TlsKeys()
	if err != nil {
		t.Fatal(err)
	}
	selfSigned, err := fixture.keys.state.selfSigned(current, fixture.networkSet(), fixture.clock.Now())
	if err != nil || !tlsCertOnKey(selfSigned, current) {
		t.Errorf("no self-signed fallback on the device key: %v", err)
	}
	// the pass does not order a revoked certificate again by itself
	if fixture.api.orderCount() != 1 {
		t.Errorf("%d orders after a revocation", fixture.api.orderCount())
	}
}

func TestTlsCertManagerRevokeStopsServingBeforeTheCaHears(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	certId := fixture.api.lastRow().CertId
	if err := fixture.manager.RevokeTlsCertificate(t.Context(), certId, true); err != nil {
		t.Fatal(err)
	}
	if len(fixture.api.revokes) != 1 || !fixture.api.revokes[0].KeyCompromise {
		t.Fatalf("revocations %+v", fixture.api.revokes)
	}
	if fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now()) != nil {
		t.Errorf("a certificate marked for revocation still serves")
	}
}

func TestTlsCertManagerRefusesAChainThatIsNotItsOwn(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	current, _, err := fixture.keys.TlsKeys()
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrOn := func(signer any, names []string) []byte {
		var der []byte
		var err error
		switch key := signer.(type) {
		case *TlsDeviceKey:
			der, err = x509.CreateCertificateRequest(cryptorand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
		case *ecdsa.PrivateKey:
			der, err = x509.CreateCertificateRequest(cryptorand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
		}
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	ownCsr := csrOn(current, fixture.networkSet())
	good := fixture.api.chainFor(ownCsr, nil, tlsCertTestLifetime)
	cases := []struct {
		name  string
		chain [][]byte
	}{
		{name: "another key", chain: fixture.api.chainFor(csrOn(otherKey, fixture.networkSet()), nil, tlsCertTestLifetime)},
		{name: "a name beyond the set", chain: fixture.api.chainFor(ownCsr, append(fixture.networkSet(), "extra."+tlsCertTestRoot), tlsCertTestLifetime)},
		{name: "a name short of the set", chain: fixture.api.chainFor(ownCsr, fixture.networkSet()[:1], tlsCertTestLifetime)},
		{name: "past its validity", chain: fixture.api.chainFor(ownCsr, nil, -time.Second)},
		{name: "a leaf that does not parse", chain: [][]byte{[]byte("not a certificate"), good[1]}},
		{name: "a link not signed by the next", chain: [][]byte{good[0], good[0]}},
		{name: "empty", chain: [][]byte{}},
		{name: "past the chain bound", chain: slices.Repeat([][]byte{good[0]}, fixture.settings.CertChainMaxCount+1)},
	}
	for _, c := range cases {
		if _, err := fixture.manager.checkChain(c.chain, current, fixture.networkSet(), fixture.clock.Now()); !errors.Is(err, ErrTlsCertChain) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := fixture.manager.checkChain(good, current, fixture.networkSet(), fixture.clock.Now()); err != nil {
		t.Errorf("the device's own chain: %v", err)
	}
}

func TestTlsCertManagerOrdersNothingUnconfiguredOrOffline(t *testing.T) {
	fixture := newTlsCertFixture(t)
	if _, err := fixture.manager.EnsureTlsCertificate(t.Context()); !errors.Is(err, ErrTlsCertsOffline) {
		t.Errorf("with no generation attached: %v", err)
	}
	if err := fixture.sync(); !errors.Is(err, ErrTlsCertsOffline) {
		t.Errorf("a pass with no generation attached: %v", err)
	}
	fixture.settings.CertsResource = ""
	fixture.attach()
	if _, err := fixture.manager.EnsureTlsCertificate(t.Context()); !errors.Is(err, ErrTlsCertsUnconfigured) {
		t.Errorf("with no certs audience: %v", err)
	}
	if fixture.api.orderCount() != 0 {
		t.Errorf("%d orders", fixture.api.orderCount())
	}
}

func TestTlsCertManagerAnOrderThatFailsEndsTheWait(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	errs := make(chan error, 1)
	go func() {
		_, err := fixture.manager.EnsureTlsCertificate(t.Context())
		errs <- err
	}()
	fixture.clock.awaitTimer(t, fixture.settings.CertOrderPollInterval)
	fixture.api.setState(fixture.api.lastRow().CertId, TlsCertStateFailed)
	fixture.clock.advance(fixture.settings.CertOrderPollInterval)
	if err := <-errs; !errors.Is(err, ErrTlsCertOrderFailed) {
		t.Fatalf("a failed order: %v", err)
	}
	// certs' refusal is answered as it came
	fixture.api.orderErr = &SidecarApiError{Route: tlsCertOrderRoute, Status: 403}
	var apiErr *SidecarApiError
	if _, err := fixture.manager.EnsureTlsCertificate(t.Context()); !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Errorf("a refused order: %v", err)
	}
}

func TestTlsCertManagerBacksOffAfterARefusedBackgroundOrder(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.setCustomHosts(tlsCertTestCustom)
	fixture.api.orderErr = &SidecarApiError{Route: tlsCertOrderRoute, Status: 409, Code: "no_account"}
	if err := fixture.sync(); err == nil {
		t.Fatalf("a refused order passed")
	}
	fixture.api.orderErr = nil
	// inside the backoff nothing is tried again
	fixture.mustSync()
	if fixture.api.orderCount() != 0 {
		t.Fatalf("%d orders inside the backoff", fixture.api.orderCount())
	}
	fixture.clock.advance(fixture.settings.CertRetryMinInterval)
	fixture.mustSync()
	if fixture.api.orderCount() != 1 {
		t.Errorf("%d orders after the backoff", fixture.api.orderCount())
	}
}

func TestTlsCertManagerQueuesOneCsrACustomHost(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.setCustomHosts(tlsCertTestCustom)
	fixture.mustSync()
	if fixture.api.orderCount() != 1 {
		t.Fatalf("%d orders for a custom host with no row", fixture.api.orderCount())
	}
	order := fixture.api.lastOrder()
	if order.Replaces != "" {
		t.Errorf("a custom order names a predecessor: the server does")
	}
	csr, err := x509.ParseCertificateRequest(order.Csr)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(csr.DNSNames, []string{tlsCertTestCustom}) {
		t.Errorf("the csr names %v", csr.DNSNames)
	}
	current, _, err := fixture.keys.TlsKeys()
	if err != nil {
		t.Fatal(err)
	}
	customSet, err := TlsCustomIdentifierSet(tlsCertTestCustom, []string{tlsCertTestRoot})
	if err != nil {
		t.Fatal(err)
	}
	customSetSha256, err := TlsIdentifierSetHash(customSet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTlsKeyAttestation(order.Attestation, testTlsIdentityPublicKey(fixture.identity), fixture.networkId, fixture.sidecarId, current.SpkiSha256(), customSetSha256); err != nil {
		t.Errorf("the attestation is not over the one host's set: %v", err)
	}
	// a second pass, and a restart's, queue none: the row is open
	fixture.mustSync()
	restarted := fixture.newManager()
	restarted.SetApi(fixture.api)
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if fixture.api.orderCount() != 1 {
		t.Errorf("%d orders after later passes", fixture.api.orderCount())
	}
	// the network's certificate was never asked for, so the pass ordered none
	if _, err := fixture.manager.PublishCertificate(fixture.networkSet()); !errors.Is(err, ErrTlsNoIssuedCertificate) {
		t.Errorf("a network certificate with none ordered: %v", err)
	}
}

func TestTlsCertManagerAnOpenCustomRowQueuesNone(t *testing.T) {
	for _, state := range []TlsCertState{TlsCertStateCustomQueued, TlsCertStateCustomOrdering} {
		fixture := newAttachedTlsCertFixture(t)
		current, _, err := fixture.keys.TlsKeys()
		if err != nil {
			t.Fatal(err)
		}
		customSetSha256, err := TlsIdentifierSetHash([]string{tlsCertTestCustom})
		if err != nil {
			t.Fatal(err)
		}
		spkiSha256 := current.SpkiSha256()
		fixture.api.addRow(&TlsCertRecord{
			CertId:              NewId(),
			NetworkId:           fixture.networkId,
			SidecarId:           fixture.sidecarId,
			IdentifierSetSha256: customSetSha256[:],
			SpkiSha256:          spkiSha256[:],
			State:               state,
		})
		fixture.setCustomHosts(tlsCertTestCustom)
		fixture.mustSync()
		fixture.mustSync()
		if fixture.api.orderCount() != 0 {
			t.Errorf("%d orders with a %s row", fixture.api.orderCount(), state)
		}
	}
}

func TestTlsCertManagerACustomHostUnderARootIsRefused(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.setCustomHosts("app." + tlsCertTestLabel + "." + tlsCertTestRoot)
	if err := fixture.sync(); !errors.Is(err, ErrTlsIdentifierSet) {
		t.Errorf("a custom host under the root: %v", err)
	}
	if fixture.api.orderCount() != 0 {
		t.Errorf("%d orders", fixture.api.orderCount())
	}
}

func TestTlsCertManagerInstallsOnlyItsOwnCustomChain(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.setCustomHosts(tlsCertTestCustom)
	fixture.mustSync()
	row := fixture.api.lastRow()
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherCsr, err := x509.CreateCertificateRequest(cryptorand.Reader, &x509.CertificateRequest{DNSNames: []string{tlsCertTestCustom}}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	good := fixture.api.chainFor(row.Csr, nil, tlsCertTestLifetime)
	cases := []struct {
		name  string
		chain [][]byte
	}{
		{name: "another key", chain: fixture.api.chainFor(otherCsr, nil, tlsCertTestLifetime)},
		{name: "a second name", chain: fixture.api.chainFor(row.Csr, []string{tlsCertTestCustom, "www.customer.example"}, tlsCertTestLifetime)},
		{name: "another host", chain: fixture.api.chainFor(row.Csr, []string{"www.customer.example"}, tlsCertTestLifetime)},
		{name: "does not parse", chain: [][]byte{[]byte("not a certificate")}},
	}
	for _, c := range cases {
		func() {
			fixture.api.stateLock.Lock()
			defer fixture.api.stateLock.Unlock()
			for _, apiRow := range fixture.api.rows {
				if apiRow.CertId == row.CertId {
					apiRow.State = TlsCertStateCustomIssued
					apiRow.Chain = c.chain
				}
			}
		}()
		if err := fixture.sync(); !errors.Is(err, ErrTlsCertChain) {
			t.Errorf("%s: %v", c.name, err)
		}
		if certificates := fixture.manager.CustomCertificates(); len(certificates) != 0 {
			t.Errorf("%s: installed", c.name)
		}
	}
	func() {
		fixture.api.stateLock.Lock()
		defer fixture.api.stateLock.Unlock()
		for _, apiRow := range fixture.api.rows {
			if apiRow.CertId == row.CertId {
				apiRow.Chain = good
			}
		}
	}()
	fixture.mustSync()
	certificates := fixture.manager.CustomCertificates()
	if len(certificates) != 1 || certificates[0].Host != tlsCertTestCustom || !bytes.Equal(certificates[0].Certificate.Certificate[0], good[0]) {
		t.Fatalf("the device's own chain was not installed")
	}
}

func TestTlsCertManagerCustomPredecessorAndSuccessor(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.setCustomHosts(tlsCertTestCustom)
	version, changed := fixture.manager.WatchCustomCertificates()
	fixture.mustSync()
	select {
	case <-changed:
		t.Fatalf("the signal fired with nothing installed")
	default:
	}
	predecessorId := fixture.api.lastRow().CertId
	fixture.api.issue(predecessorId, 10*24*time.Hour)
	fixture.mustSync()
	// the signal fires on install
	<-changed
	installedVersion, changed := fixture.manager.WatchCustomCertificates()
	if installedVersion <= version {
		t.Errorf("the version did not rise on install")
	}
	predecessor := fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, fixture.clock.Now())
	if predecessor == nil {
		t.Fatalf("the installed custom certificate does not serve")
	}
	// a live certificate queues nothing
	fixture.mustSync()
	if fixture.api.orderCount() != 1 {
		t.Fatalf("%d orders with a live certificate", fixture.api.orderCount())
	}

	// the sweep queues a successor with the old CSR: the predecessor serves until the successor's chain arrives
	fixture.clock.advance(7 * 24 * time.Hour)
	successor := fixture.api.lastRow()
	successor.CertId = NewId()
	successor.State = TlsCertStateCustomQueued
	successor.Chain = nil
	fixture.api.addRow(successor)
	fixture.mustSync()
	served := fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, fixture.clock.Now())
	if served == nil || !bytes.Equal(served.Certificate[0], predecessor.Certificate[0]) {
		t.Fatalf("the predecessor stopped serving while its successor waited")
	}
	fixture.api.issue(successor.CertId, tlsCertTestLifetime)
	fixture.mustSync()
	<-changed
	_, changed = fixture.manager.WatchCustomCertificates()
	served = fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, fixture.clock.Now())
	if served == nil || bytes.Equal(served.Certificate[0], predecessor.Certificate[0]) {
		t.Fatalf("the successor does not serve from its install")
	}
	// the predecessor is kept beside it until it expires
	if infos := fixture.manager.Certificates(); len(infos) != 2 {
		t.Fatalf("%d certificates with a predecessor kept", len(infos))
	}
	// should the successor's row stop reading custom_issued, the predecessor serves again
	fixture.api.setState(successor.CertId, TlsCertStateCustomRevoking)
	fixture.mustSync()
	<-changed
	_, changed = fixture.manager.WatchCustomCertificates()
	served = fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, fixture.clock.Now())
	if served == nil || !bytes.Equal(served.Certificate[0], predecessor.Certificate[0]) {
		t.Fatalf("a revoking successor still serves, or the predecessor does not")
	}
	fixture.api.setState(successor.CertId, TlsCertStateCustomIssued)
	fixture.mustSync()
	<-changed
	_, changed = fixture.manager.WatchCustomCertificates()

	// the predecessor's expiry drops it and fires the signal
	fixture.clock.advance(3*24*time.Hour + time.Minute)
	fixture.mustSync()
	<-changed
	if infos := fixture.manager.Certificates(); len(infos) != 1 || infos[0].CertId != successor.CertId {
		t.Errorf("certificates after the predecessor expired %+v", infos)
	}
	if fixture.api.orderCount() != 1 {
		t.Errorf("%d orders: the device queued a renewal the sweep owns", fixture.api.orderCount())
	}
}

func TestTlsCertManagerACustomRowThatIsNotIssuedStopsServingAtOnce(t *testing.T) {
	for _, state := range []TlsCertState{TlsCertStateCustomRevoking, TlsCertStateRevoked, TlsCertStateExpired, TlsCertState("a_state_from_later")} {
		fixture := newAttachedTlsCertFixture(t)
		fixture.setCustomHosts(tlsCertTestCustom)
		fixture.mustSync()
		certId := fixture.api.lastRow().CertId
		fixture.api.issue(certId, tlsCertTestLifetime)
		fixture.mustSync()
		_, changed := fixture.manager.WatchCustomCertificates()
		if fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, fixture.clock.Now()) == nil {
			t.Fatalf("an issued custom certificate does not serve")
		}
		fixture.api.setState(certId, state)
		// the names source failing does not keep a revocation from applying
		func() {
			fixture.stateLock.Lock()
			defer fixture.stateLock.Unlock()
			fixture.namesErr = errors.New("the zone is unreachable")
		}()
		if err := fixture.sync(); err == nil {
			t.Fatalf("a pass with no names passed")
		}
		if fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, fixture.clock.Now()) != nil {
			t.Errorf("a custom certificate whose row reads %s still serves", state)
		}
		if len(fixture.manager.CustomCertificates()) != 0 {
			t.Errorf("a custom certificate whose row reads %s is still listed", state)
		}
		// the signal fires on revocation
		select {
		case <-changed:
		default:
			t.Errorf("no signal when the row came to %s", state)
		}
	}
}

func TestTlsCertManagerALostCustomRowQueuesAgain(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.setCustomHosts(tlsCertTestCustom)
	fixture.mustSync()
	certId := fixture.api.lastRow().CertId
	fixture.api.issue(certId, tlsCertTestLifetime)
	fixture.mustSync()
	// a restore behind the row: no row certifies the chain, so it is not presented, and the CSR is queued again
	fixture.api.removeRow(certId)
	fixture.mustSync()
	if fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, fixture.clock.Now()) != nil {
		t.Errorf("a custom chain no row names still serves")
	}
	if fixture.api.orderCount() != 2 {
		t.Errorf("%d orders after the row was lost", fixture.api.orderCount())
	}
}

func TestTlsCertManagerASuccessorFailedForAttestationQueuesANewCsr(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.setCustomHosts(tlsCertTestCustom)
	fixture.mustSync()
	fixture.api.issue(fixture.api.lastRow().CertId, tlsCertTestLifetime)
	fixture.mustSync()

	// the sweep's successor fails at the ordering desktop for another reason: the live certificate serves on, and
	// the device queues nothing
	failed := fixture.api.lastRow()
	failed.CertId = NewId()
	failed.State = TlsCertStateFailed
	failed.Chain = nil
	failed.CustomReason = "ca_refused"
	fixture.api.addRow(failed)
	fixture.mustSync()
	if fixture.api.orderCount() != 1 {
		t.Fatalf("%d orders after a successor failed at its CA", fixture.api.orderCount())
	}

	// one that failed for its attestation asks for a new CSR, once
	attestation := fixture.api.lastRow()
	attestation.CertId = NewId()
	attestation.State = TlsCertStateFailed
	attestation.Chain = nil
	attestation.CustomReason = TlsCustomReasonAttestation
	fixture.api.addRow(attestation)
	fixture.mustSync()
	if fixture.api.orderCount() != 2 {
		t.Fatalf("%d orders after a successor failed for its attestation", fixture.api.orderCount())
	}
	fixture.mustSync()
	if fixture.api.orderCount() != 2 {
		t.Errorf("%d orders after a second pass", fixture.api.orderCount())
	}
	if fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, fixture.clock.Now()) == nil {
		t.Errorf("the live certificate stopped serving")
	}
}

func TestTlsCertManagerNeverCrossesNetworkAndCustomCertificates(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	network := fixture.ensureIssued()
	fixture.setCustomHosts(tlsCertTestCustom)
	fixture.mustSync()
	fixture.api.issue(fixture.api.lastRow().CertId, tlsCertTestLifetime)
	fixture.mustSync()
	now := fixture.clock.Now()

	custom := fixture.manager.IssuedTlsCertificate([]string{tlsCertTestCustom}, now)
	if custom == nil || !slices.Equal(custom.Leaf.DNSNames, []string{tlsCertTestCustom}) {
		t.Fatalf("the custom host's certificate %v", custom)
	}
	if bytes.Equal(custom.Certificate[0], network.Certificate[0]) {
		t.Errorf("the network's certificate answers a custom host")
	}
	served := fixture.manager.IssuedTlsCertificate(fixture.networkSet(), now)
	if served == nil || !bytes.Equal(served.Certificate[0], network.Certificate[0]) {
		t.Errorf("the network's names are not answered by the network's certificate")
	}
	// neither covers the two together, nor a custom host the device holds nothing for
	if fixture.manager.IssuedTlsCertificate(append(fixture.networkSet(), tlsCertTestCustom), now) != nil {
		t.Errorf("one certificate answers a network name and a custom host")
	}
	if fixture.manager.IssuedTlsCertificate([]string{"www.customer.example"}, now) != nil {
		t.Errorf("a custom host with no certificate is answered")
	}
	// a custom row forged with the network's names never installs as custom, nor the other way
	current, _, err := fixture.keys.TlsKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.checkChain(network.Certificate, current, []string{tlsCertTestCustom}, now); !errors.Is(err, ErrTlsCertChain) {
		t.Errorf("the network's chain checked as a custom host's: %v", err)
	}
	if _, err := fixture.manager.checkChain(custom.Certificate, current, fixture.networkSet(), now); !errors.Is(err, ErrTlsCertChain) {
		t.Errorf("a custom chain checked as the network's: %v", err)
	}
}

func TestTlsCertManagerIgnoresAnotherSidecarsRows(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	certificate := fixture.ensureIssued()
	row := fixture.api.lastRow()
	// another device's issued row for the same set, and one of this device's id in another network
	other := *row
	other.CertId = NewId()
	other.SidecarId = tlsCertTestId("another sidecar")
	fixture.api.addRow(&other)
	foreign := *row
	foreign.CertId = NewId()
	foreign.NetworkId = tlsCertTestId("another network")
	fixture.api.addRow(&foreign)
	fixture.mustSync()
	if infos := fixture.manager.Certificates(); len(infos) != 1 || infos[0].CertId != row.CertId {
		t.Errorf("certificates %+v", infos)
	}
	served := fixture.manager.IssuedTlsCertificate(fixture.networkSet(), fixture.clock.Now())
	if served == nil || !bytes.Equal(served.Certificate[0], certificate.Certificate[0]) {
		t.Errorf("the device's own certificate does not serve")
	}
}

func TestTlsCertManagerSignsALabelReclaim(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	proof := &DnsReclaimProof{
		Name:       tlsCertTestLabel + "." + tlsCertTestRoot,
		NetworkId:  fixture.networkId,
		IncidentId: tlsCertTestId("restore incident"),
	}
	if _, err := fixture.manager.SignLabelReclaim(t.Context(), proof); !errors.Is(err, ErrTlsNoIssuedCertificate) {
		t.Fatalf("a reclaim with no certificate: %v", err)
	}
	fixture.ensureIssued()
	reclaim, err := fixture.manager.SignLabelReclaim(t.Context(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDnsReclaimProof(proof, reclaim.LeafDer, reclaim.Signature); err != nil {
		t.Errorf("the reclaim does not verify: %v", err)
	}
	// over one name, network and incident only
	otherIncident := *proof
	otherIncident.IncidentId = tlsCertTestId("another incident")
	if err := VerifyDnsReclaimProof(&otherIncident, reclaim.LeafDer, reclaim.Signature); err == nil {
		t.Errorf("the signature fits another incident")
	}
	// a name this device's certificate does not name is not signed for
	otherName := *proof
	otherName.Name = "zzzzzzzzzz." + tlsCertTestRoot
	if _, err := fixture.manager.SignLabelReclaim(t.Context(), &otherName); !errors.Is(err, ErrTlsNoIssuedCertificate) {
		t.Errorf("a reclaim for another name: %v", err)
	}
}

func TestTlsAriCertificateIdKeepsTheSerialsLeadingZero(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	leaf := tlsCertLeafOf(t, fixture.ensureIssued())
	certificateId := tlsAriCertificateId(leaf)
	aki, serial, found := strings.Cut(certificateId, ".")
	if !found || aki != "AQIDBA" {
		t.Fatalf("certificate id %q", certificateId)
	}
	// 0x80000001 in DER is 00 80 00 00 01: RFC 9773 takes the content octets, sign octet included
	if serial != "AIAAAAE" {
		t.Errorf("serial part %q", serial)
	}
	if tlsAriCertificateId(&x509.Certificate{SerialNumber: big.NewInt(1)}) != "" {
		t.Errorf("an id for a leaf with no authority key identifier")
	}
}

// D-TLS-7: no mobile build needs an ACME client, so the manager and its component import none.
func TestTlsCertManagerImportsNoAcmeClient(t *testing.T) {
	for _, name := range []string{"tls_cert_manager.go", "tls_component.go", "tls_api_client.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			if strings.Contains(strings.ToLower(spec.Path.Value), "acme") {
				t.Errorf("%s imports %s", name, spec.Path.Value)
			}
		}
	}
}

func TestNewTlsCertManagerRefusesMissingParts(t *testing.T) {
	if _, err := NewTlsCertManager(t.Context(), nil); !errors.Is(err, errInvalidSettings) {
		t.Errorf("nil args: %v", err)
	}
	if _, err := NewTlsCertManager(t.Context(), &TlsCertManagerArgs{NetworkId: testNetworkId}); !errors.Is(err, errInvalidSettings) {
		t.Errorf("no sidecar: %v", err)
	}
}
