// The chains' passes on a fake clock, store, Redis and Push, and a scripted CA (TLS-M5-17): an order to
// its certificate, each way an order ends, a pass taken up where another stopped, renewals from the
// stored CSR past every limit, the revocation sweep with no call from another area, and a hint for each
// move. Nothing here sleeps: a pass that must be cut short is cut by its own CA call.

package certsservice_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A CA that issues each CSR a leaf on its key under one issuer, unless its script says otherwise.
type testRunAcme struct {
	t         *testing.T
	clock     *sidecartest.FakeClock
	issuerKey *ecdsa.PrivateKey
	issuer    *x509.Certificate

	stateLock sync.Mutex
	// what the next orders answer, first in first out; nil issues
	orderErrs []error
	// runs inside an order before it answers
	orderHook  func(ctx context.Context)
	orders     []*certsservice.CertsAcmeOrder
	nextSerial int64
	// the window RenewalInfo answers, zero for a CA with no ARI
	windowStart time.Time
	windowEnd   time.Time
	revoked     []testRevocation
	revokeErr   error
}

type testRevocation struct {
	ca     certsservice.CertsCa
	serial string
	reason certsservice.CertsRevocationReason
}

func newTestRunAcme(t *testing.T, clock *sidecartest.FakeClock) *testRunAcme {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		// a name of its own, so a leaf is not read as self-signed and carries its authority key id
		Subject:               pkix.Name{CommonName: "Test Issuer"},
		NotBefore:             clock.Now().Add(-time.Hour),
		NotAfter:              clock.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testRunAcme{t: t, clock: clock, issuerKey: issuerKey, issuer: issuer, nextSerial: 0x1000}
}

func (self *testRunAcme) Order(ctx context.Context, order *certsservice.CertsAcmeOrder) (*certsservice.CertsAcmeIssued, error) {
	self.stateLock.Lock()
	self.orders = append(self.orders, order)
	var scripted error
	if 0 < len(self.orderErrs) {
		scripted = self.orderErrs[0]
		self.orderErrs = self.orderErrs[1:]
	}
	hook := self.orderHook
	self.nextSerial += 1
	serial := big.NewInt(self.nextSerial)
	self.stateLock.Unlock()
	if hook != nil {
		hook(ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if scripted != nil {
		return nil, scripted
	}
	csr, err := x509.ParseCertificateRequest(order.Csr)
	if err != nil {
		return nil, err
	}
	now := self.clock.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		DNSNames:     csr.DNSNames,
		NotBefore:    now,
		NotAfter:     now.Add(45 * 24 * time.Hour),
	}
	leaf, err := x509.CreateCertificate(rand.Reader, template, self.issuer, csr.PublicKey, self.issuerKey)
	if err != nil {
		return nil, err
	}
	return &certsservice.CertsAcmeIssued{
		Chain:      [][]byte{leaf, self.issuer.Raw},
		AccountUri: "https://ca.example/acct/1",
		Serial:     certsservice.CertsSerialText(serial),
		NotBefore:  template.NotBefore,
		NotAfter:   template.NotAfter,
	}, nil
}

func (self *testRunAcme) RenewalInfo(ctx context.Context, ca certsservice.CertsCa, leaf []byte) (time.Time, time.Time, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.windowStart.IsZero() {
		return time.Time{}, time.Time{}, errors.New("the CA has no ARI")
	}
	return self.windowStart, self.windowEnd, nil
}

func (self *testRunAcme) Revoke(ctx context.Context, ca certsservice.CertsCa, leaf []byte, reason certsservice.CertsRevocationReason) error {
	certificate, err := x509.ParseCertificate(leaf)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.revokeErr != nil {
		return self.revokeErr
	}
	self.revoked = append(self.revoked, testRevocation{ca: ca, serial: certsservice.CertsSerialText(certificate.SerialNumber), reason: reason})
	return nil
}

func (self *testRunAcme) script(errs ...error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.orderErrs = append(self.orderErrs, errs...)
}

func (self *testRunAcme) setOrderHook(hook func(ctx context.Context)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.orderHook = hook
}

func (self *testRunAcme) setWindow(windowStart time.Time, windowEnd time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.windowStart = windowStart
	self.windowEnd = windowEnd
}

func (self *testRunAcme) ordered() []*certsservice.CertsAcmeOrder {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.orders)
}

func (self *testRunAcme) revocations() []testRevocation {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.revoked)
}

// A leaf the CA would issue device for its set, with serial, valid 45 days from notBefore.
func (self *testRunAcme) leaf(device *testDevice, serial *big.Int, notBefore time.Time) []byte {
	self.t.Helper()
	template := &x509.Certificate{
		SerialNumber: serial,
		DNSNames:     device.identifierSet,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(45 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, self.issuer, &device.tlsKey.PublicKey, self.issuerKey)
	if err != nil {
		self.t.Fatal(err)
	}
	return der
}

// The causes a host reads, by row.
type testRevocationSource struct {
	stateLock sync.Mutex
	causes    map[sidecar.Id]certsservice.CertsRevocationCause
	asked     [][]sidecar.Id
	names     map[sidecar.Id][]string
	err       error
}

func newTestRevocationSource() *testRevocationSource {
	return &testRevocationSource{causes: map[sidecar.Id]certsservice.CertsRevocationCause{}, names: map[sidecar.Id][]string{}}
}

func (self *testRevocationSource) RevocationCauses(ctx context.Context, candidates []*certsservice.CertsRevocationCandidate) (map[sidecar.Id]certsservice.CertsRevocationCause, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return nil, self.err
	}
	asked := []sidecar.Id{}
	causes := map[sidecar.Id]certsservice.CertsRevocationCause{}
	for _, candidate := range candidates {
		asked = append(asked, candidate.Cert.CertId)
		self.names[candidate.Cert.CertId] = candidate.Names
		if cause, found := self.causes[candidate.Cert.CertId]; found {
			causes[candidate.Cert.CertId] = cause
		}
	}
	self.asked = append(self.asked, asked)
	return causes, nil
}

func (self *testRevocationSource) set(certId sidecar.Id, cause certsservice.CertsRevocationCause) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.causes[certId] = cause
}

// A service whose CA is acme.
type testRun struct {
	*testCerts
	acme *testRunAcme
}

func newTestRun(t *testing.T, settings *certsservice.CertsSettings) *testRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if settings == nil {
		settings = testSettings()
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterCertsBudgetTwins(host.Redis)
	store := sidecartest.NewFakeCertsStore(host.Redis.Faults())
	acme := newTestRunAcme(t, clock)
	service, err := certsservice.NewCertsService(ctx, host.ServiceHost(), store, nil, acme, settings)
	if err != nil {
		t.Fatal(err)
	}
	return &testRun{
		testCerts: &testCerts{t: t, ctx: ctx, clock: clock, host: host, store: store, settings: settings, service: service},
		acme:      acme,
	}
}

// A device of a new network whose label is label.
func (self *testRun) device(label string) *testDevice {
	self.t.Helper()
	return newTestDevice(self.t, label)
}

func (self *testRun) runOrders() *certsservice.CertsOrdersReport {
	self.t.Helper()
	report, err := self.service.RunOrders(self.ctx, sidecar.Id{})
	if err != nil {
		self.t.Fatal(err)
	}
	return report
}

func (self *testRun) runRenewals() *certsservice.CertsRenewalsReport {
	self.t.Helper()
	report, err := self.service.RunRenewals(self.ctx, sidecar.Id{})
	if err != nil {
		self.t.Fatal(err)
	}
	return report
}

func (self *testRun) runRevocations(source certsservice.CertsRevocationSource) *certsservice.CertsRevocationsReport {
	self.t.Helper()
	report, err := self.service.RunRevocations(self.ctx, source, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return report
}

// The TlsHints the device's client was told: each one's kind and row.
func (self *testRun) hints(device *testDevice) []*protocol.TlsHint {
	self.t.Helper()
	hints := []*protocol.TlsHint{}
	for _, clientHint := range self.host.Push.Hints(connect.Id(device.clientId)) {
		if clientHint.Topic != sidecar.PushTopicTls || clientHint.Kind != uint32(protocol.MessageType_TLS_HINT) {
			self.t.Fatalf("a hint on topic %q of kind %#x", clientHint.Topic, clientHint.Kind)
		}
		if clientHint.Version == 0 {
			self.t.Fatal("a hint with no version")
		}
		hint := &protocol.TlsHint{}
		if err := proto.Unmarshal(clientHint.Body, hint); err != nil {
			self.t.Fatal(err)
		}
		hints = append(hints, hint)
	}
	return hints
}

func (self *testRun) hintKinds(device *testDevice, certId sidecar.Id) []protocol.TlsHintKind {
	self.t.Helper()
	kinds := []protocol.TlsHintKind{}
	for _, hint := range self.hints(device) {
		if sidecar.Id(hint.CertId) == certId {
			kinds = append(kinds, hint.Kind)
		}
	}
	return kinds
}

// A row of device's, issued at ca with a chain the CA made, as a row holds one once it keeps its
// chain: written whole, since no pass writes a chain yet.
func (self *testRun) issuedWithChain(device *testDevice, ca certsservice.CertsCa, serial *big.Int) *sidecar.TlsCertRecord {
	self.t.Helper()
	now := self.clock.Now()
	leaf := self.acme.leaf(device, serial, now)
	spkiSha256 := testSpkiSha256(self.t, &device.tlsKey.PublicKey)
	setSha256, err := sidecar.TlsIdentifierSetHash(device.identifierSet)
	if err != nil {
		self.t.Fatal(err)
	}
	row := &sidecar.TlsCertRecord{
		CertId:              sidecartest.CertsIdAt(now),
		NetworkId:           device.networkId,
		ClientId:            device.clientId,
		SidecarId:           device.sidecarId,
		IdentifierSetSha256: setSha256[:],
		SpkiSha256:          spkiSha256[:],
		Attestation:         device.attestation(self.t),
		Csr:                 testCsr(self.t, device.tlsKey, device.identifierSet),
		Ca:                  string(ca),
		AccountUri:          "https://ca.example/acct/1",
		Profile:             "tlsserver",
		Serial:              certsservice.CertsSerialText(serial),
		NotBefore:           now,
		NotAfter:            now.Add(45 * 24 * time.Hour),
		State:               sidecar.TlsCertStateIssued,
		Chain:               [][]byte{leaf, self.acme.issuer.Raw},
	}
	if err := self.store.InsertCert(self.ctx, row); err != nil {
		self.t.Fatal(err)
	}
	return row
}

// An order goes from the queue to its certificate in one pass: admitted to LE, ordered with the stored
// CSR and the CA's profile, and its row issued with the serial, the validity and the CA's ARI window.
// Its device is told of the order and of the issuance.
func TestCertsRunOrdersIssues(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9runord01")
	certId := run.accept(device)
	windowStart := run.clock.Now().Add(28 * 24 * time.Hour)
	run.acme.setWindow(windowStart, windowStart.Add(48*time.Hour))

	report := run.runOrders()
	if report.Unavailable || !slices.Equal(report.Admitted, []sidecar.Id{certId}) || !slices.Equal(report.Issued, []sidecar.Id{certId}) ||
		len(report.Failed)+len(report.Requeued)+len(report.Interrupted)+len(report.Resumed) != 0 || report.More {
		t.Fatalf("report %+v", report)
	}
	orders := run.acme.ordered()
	if len(orders) != 1 || orders[0].Ca != certsservice.CertsCaLetsEncrypt || orders[0].Profile != "tlsserver" || orders[0].Replaces != "" {
		t.Fatalf("orders %+v", orders)
	}
	row := run.row(certId)
	if string(orders[0].Csr) != string(row.Csr) {
		t.Fatal("the CA was not sent the stored CSR")
	}
	if row.State != sidecar.TlsCertStateIssued || row.Serial == "" || row.AccountUri != "https://ca.example/acct/1" ||
		!row.NotBefore.Equal(run.clock.Now()) || !row.NotAfter.Equal(run.clock.Now().Add(45*24*time.Hour)) ||
		!row.AriWindowStart.Equal(windowStart) || !row.AriWindowEnd.Equal(windowStart.Add(48*time.Hour)) {
		t.Fatalf("row %+v", row)
	}
	if kinds := run.hintKinds(device, certId); !slices.Equal(kinds, []protocol.TlsHintKind{protocol.TlsHintKind_TLS_HINT_ORDER, protocol.TlsHintKind_TLS_HINT_ISSUED}) {
		t.Fatalf("hints %v", kinds)
	}
	if report.Hints.Sent != 2 || report.Hints.Failed != 0 {
		t.Fatalf("hint counts %+v", report.Hints)
	}
	// nothing is left for a second pass
	if again := run.runOrders(); len(again.Admitted)+len(again.Resumed)+len(again.Issued) != 0 || len(run.acme.ordered()) != 1 {
		t.Fatalf("a second pass %+v", again)
	}
}

// A host with no ACME client admits nothing: the row stays queued, no budget is spent and no hint goes.
func TestCertsRunOrdersWithNoCaAdmitsNothing(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "k9runord02")
	certId := certs.accept(device)
	report, err := certs.service.RunOrders(certs.ctx, sidecar.Id{})
	if err != nil || !report.Unavailable || len(report.Admitted) != 0 {
		t.Fatalf("report %+v, %v", report, err)
	}
	if state := certs.row(certId).State; state != sidecar.TlsCertStateQueued {
		t.Fatalf("state %s", state)
	}
	members, err := sidecartest.CertsBudgetMembers(certs.ctx, certs.host.Redis, "{tcb_letsencrypt_"+testRoot+"}")
	if err != nil || len(members) != 0 {
		t.Fatalf("budget %v, %v", members, err)
	}
	renewals, err := certs.service.RunRenewals(certs.ctx, sidecar.Id{})
	if err != nil || !renewals.Unavailable || len(renewals.Queued) != 0 {
		t.Fatalf("renewals %+v, %v", renewals, err)
	}
}

// A CA's refusal on a limit holds that CA and queues the order again, and the next pass takes it to the
// next CA; the device hears of each move.
func TestCertsRunOrdersRateLimitHoldsTheCa(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9runord03")
	certId := run.accept(device)
	run.acme.script(&certsservice.CertsAcmeRateLimitError{Ca: certsservice.CertsCaLetsEncrypt, RetryAfter: run.clock.Now().Add(2 * time.Hour)})

	report := run.runOrders()
	if !slices.Equal(report.Requeued, []sidecar.Id{certId}) || len(report.Issued) != 0 {
		t.Fatalf("report %+v", report)
	}
	if state := run.row(certId).State; state != sidecar.TlsCertStateQueued {
		t.Fatalf("state %s", state)
	}
	report = run.runOrders()
	if !slices.Equal(report.Issued, []sidecar.Id{certId}) {
		t.Fatalf("the second pass %+v", report)
	}
	orders := run.acme.ordered()
	if len(orders) != 2 || orders[0].Ca != certsservice.CertsCaLetsEncrypt || orders[1].Ca != certsservice.CertsCaGts {
		t.Fatalf("orders %+v", orders)
	}
	if row := run.row(certId); row.State != sidecar.TlsCertStateIssued || row.Ca != string(certsservice.CertsCaGts) {
		t.Fatalf("row %+v", row)
	}
	want := []protocol.TlsHintKind{
		protocol.TlsHintKind_TLS_HINT_ORDER, protocol.TlsHintKind_TLS_HINT_ORDER,
		protocol.TlsHintKind_TLS_HINT_ORDER, protocol.TlsHintKind_TLS_HINT_ISSUED,
	}
	if kinds := run.hintKinds(device, certId); !slices.Equal(kinds, want) {
		t.Fatalf("hints %v", kinds)
	}
}

// Failed authorizations count against the order's names: at the fourth inside the hour the name holds
// and the order waits, with no CA asked.
func TestCertsRunOrdersFailedAuthorizationsHoldTheName(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9runord04")
	certId := run.accept(device)
	for range run.settings.FailedAuthorizationCount {
		run.acme.script(&certsservice.CertsAcmeAuthorizationError{Ca: certsservice.CertsCaLetsEncrypt, Names: device.identifierSet})
		if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{certId}) {
			t.Fatalf("report %+v", report)
		}
		run.clock.Advance(time.Minute)
	}
	asked := len(run.acme.ordered())
	report := run.runOrders()
	if len(report.Admitted) != 0 || len(report.Waiting) != 1 || report.Waiting[0].Reason != certsservice.CertsWaitNameHold {
		t.Fatalf("report %+v", report)
	}
	if len(run.acme.ordered()) != asked {
		t.Fatal("a held name reached the CA")
	}
}

// An order that keeps failing queues again while it is young and fails once it is OrderGiveUpAge old;
// a row that fails does not stop the pass's other orders.
func TestCertsRunOrdersGivesUpAnOldOrder(t *testing.T) {
	settings := testSettings()
	settings.OrderConcurrency = 1
	run := newTestRun(t, settings)
	failing := run.device("k9runord05")
	failingId := run.accept(failing)
	run.acme.script(errors.New("the CA is down"))
	if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{failingId}) {
		t.Fatalf("report %+v", report)
	}
	run.clock.Advance(settings.OrderGiveUpAge)
	other := run.device("k9runord06")
	otherId := run.accept(other)
	run.acme.script(errors.New("the CA is down"))
	report := run.runOrders()
	if !slices.Equal(report.Failed, []sidecar.Id{failingId}) || !slices.Equal(report.Issued, []sidecar.Id{otherId}) {
		t.Fatalf("report %+v", report)
	}
	if state := run.row(failingId).State; state != sidecar.TlsCertStateFailed {
		t.Fatalf("state %s", state)
	}
	if kinds := run.hintKinds(failing, failingId); len(kinds) != 4 || kinds[3] != protocol.TlsHintKind_TLS_HINT_ORDER {
		t.Fatalf("hints %v", kinds)
	}
}

// A pass whose time ends while its CA answers leaves the row under way, and the next pass orders it
// again and issues it, with no second admission and no second budget unit.
func TestCertsRunOrdersResumesAnInterruptedPass(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9runord07")
	certId := run.accept(device)
	passCtx, endPass := context.WithCancel(run.ctx)
	defer endPass()
	run.acme.setOrderHook(func(ctx context.Context) {
		endPass()
		<-ctx.Done()
	})
	report, err := run.service.RunOrders(passCtx, sidecar.Id{})
	if err != nil || !slices.Equal(report.Interrupted, []sidecar.Id{certId}) || !report.More {
		t.Fatalf("report %+v, %v", report, err)
	}
	if state := run.row(certId).State; state != sidecar.TlsCertStateOrdering {
		t.Fatalf("state %s", state)
	}
	run.acme.setOrderHook(nil)
	report = run.runOrders()
	if !slices.Equal(report.Resumed, []sidecar.Id{certId}) || len(report.Admitted) != 0 || !slices.Equal(report.Issued, []sidecar.Id{certId}) {
		t.Fatalf("the next pass %+v", report)
	}
	members, err := sidecartest.CertsBudgetMembers(run.ctx, run.host.Redis, "{tcb_letsencrypt_"+testRoot+"}")
	if err != nil {
		t.Fatal(err)
	}
	// the marker and the one order
	if len(members) != 2 {
		t.Fatalf("budget %v", members)
	}
}

// A pass full of earlier work admits nothing new and asks to run again soon, keeping its place in the
// queue.
func TestCertsRunOrdersFullOfResumedWorkAdmitsNothing(t *testing.T) {
	settings := testSettings()
	settings.OrderResumeCount = 1
	run := newTestRun(t, settings)
	first := run.accept(run.device("k9runord08"))
	run.admit()
	second := run.accept(run.device("k9runord09"))
	cursor := sidecartest.CertsIdAt(run.clock.Now().Add(-time.Hour))
	report, err := run.service.RunOrders(run.ctx, cursor)
	if err != nil || !slices.Equal(report.Resumed, []sidecar.Id{first}) || len(report.Admitted) != 0 || !report.More || report.NextCertId != cursor {
		t.Fatalf("report %+v, %v", report, err)
	}
	if state := run.row(second).State; state != sidecar.TlsCertStateQueued {
		t.Fatalf("state %s", state)
	}
}

// A certificate renews from its stored CSR with its device away: due at two thirds of its life, its
// renewal queues as its successor, and the order goes to its own CA past that CA's hold and a spent
// budget, naming the certificate it replaces where its row keeps a chain. Past its validity the old row
// is expired.
func TestCertsRunRenewals(t *testing.T) {
	settings := testSettings()
	settings.Cas[certsservice.CertsCaLetsEncrypt].BudgetCap = 1
	run := newTestRun(t, settings)
	device := run.device("k9renew001")
	serial := big.NewInt(0x77aa01)
	issued := run.issuedWithChain(device, certsservice.CertsCaLetsEncrypt, serial)

	if report := run.runRenewals(); len(report.Queued) != 0 || len(report.Expired) != 0 {
		t.Fatalf("a renewal before its time: %+v", report)
	}
	run.clock.Advance(30 * 24 * time.Hour)
	report := run.runRenewals()
	if len(report.Queued) != 1 || report.Hints.Sent != 1 {
		t.Fatalf("report %+v", report)
	}
	renewalId := report.Queued[0]
	if run.row(issued.CertId).SuccessorCertId != renewalId {
		t.Fatal("the old row does not name its renewal")
	}
	if again := run.runRenewals(); len(again.Queued) != 0 {
		t.Fatalf("a certificate renewed twice: %+v", again)
	}

	// another network's first certificate takes the week's one unit, and then the CA holds
	otherId := run.accept(run.device("k9renew0zz"))
	if orders := run.runOrders(); !slices.Contains(orders.Issued, otherId) || !slices.Contains(orders.Issued, renewalId) {
		// both are admitted by one pass: the renewal past the budget, the new set under it
		t.Fatalf("orders %+v", orders)
	}
	sent := run.acme.ordered()
	if len(sent) != 2 {
		t.Fatalf("orders sent %+v", sent)
	}
	var renewalOrder *certsservice.CertsAcmeOrder
	for _, order := range sent {
		if string(order.Csr) == string(issued.Csr) {
			renewalOrder = order
		}
	}
	if renewalOrder == nil || renewalOrder.Ca != certsservice.CertsCaLetsEncrypt ||
		renewalOrder.Replaces != testCertificateId(run.acme.issuer.SubjectKeyId, serial) {
		t.Fatalf("the renewal's order %+v", renewalOrder)
	}
	// the next renewals, of those two certificates, go through a held CA with the budget spent
	run.service.HoldCa(certsservice.CertsCaLetsEncrypt, run.clock.Now().Add(60*24*time.Hour))
	run.clock.Advance(30 * 24 * time.Hour)
	second := run.runRenewals()
	if len(second.Queued) != 2 || !slices.Equal(second.Expired, []sidecar.Id{issued.CertId}) {
		t.Fatalf("the second renewal %+v", second)
	}
	if orders := run.runOrders(); !slices.Equal(orders.Issued, second.Queued) || len(orders.Waiting) != 0 {
		t.Fatalf("orders under a hold %+v", orders)
	}
	if last := run.acme.ordered()[2]; last.Ca != certsservice.CertsCaLetsEncrypt || last.Replaces != "" {
		// the renewal's own row keeps no chain yet, so its renewal names nothing
		t.Fatalf("the second renewal's order %+v", last)
	}
	if kinds := run.hintKinds(device, renewalId); !slices.Equal(kinds, []protocol.TlsHintKind{
		protocol.TlsHintKind_TLS_HINT_ORDER, protocol.TlsHintKind_TLS_HINT_ORDER, protocol.TlsHintKind_TLS_HINT_ISSUED,
	}) {
		t.Fatalf("hints %v", kinds)
	}

	if state := run.row(issued.CertId).State; state != sidecar.TlsCertStateExpired {
		t.Fatalf("state %s", state)
	}
	if state := run.row(renewalId).State; state != sidecar.TlsCertStateIssued {
		t.Fatalf("the renewal's state %s", state)
	}
}

// A renewal pass reads a kept chain's ARI window again and renews by the window the CA now gives; it
// reads at most its batch and says where the next pass starts.
func TestCertsRunRenewalsReadsTheWindowAgain(t *testing.T) {
	settings := testSettings()
	settings.RenewalBatchCount = 1
	run := newTestRun(t, settings)
	first := run.issuedWithChain(run.device("k9renew002"), certsservice.CertsCaLetsEncrypt, big.NewInt(0x77aa02))
	run.clock.Advance(time.Millisecond)
	second := run.issuedWithChain(run.device("k9renew003"), certsservice.CertsCaLetsEncrypt, big.NewInt(0x77aa03))
	// the CA wants its certificates replaced now
	run.acme.setWindow(run.clock.Now().Add(-time.Hour), run.clock.Now().Add(-time.Minute))

	report := run.runRenewals()
	if report.WindowsRead != 1 || len(report.Queued) != 1 || report.NextCertId != first.CertId {
		t.Fatalf("report %+v", report)
	}
	if row := run.row(first.CertId); row.AriWindowStart.IsZero() || row.SuccessorCertId != report.Queued[0] {
		t.Fatalf("row %+v", row)
	}
	next, err := run.service.RunRenewals(run.ctx, report.NextCertId)
	if err != nil || len(next.Queued) != 1 || run.row(second.CertId).SuccessorCertId != next.Queued[0] {
		t.Fatalf("the next pass %+v, %v", next, err)
	}
}

// The sweep revokes a removed device's certificate with no call from any other area: the host's rows
// say the client is gone, the row is marked and its CA told cessationOfOperation in the same pass, a
// CA's hold and a spent budget notwithstanding, and the device is told. A compromise is told
// keyCompromise. A certificate with no cause stays.
func TestCertsRunRevocationsSweeps(t *testing.T) {
	run := newTestRun(t, nil)
	removed := run.device("k9revoke01")
	removedRow := run.issuedWithChain(removed, certsservice.CertsCaLetsEncrypt, big.NewInt(0x88bb01))
	run.clock.Advance(time.Millisecond)
	compromised := run.device("k9revoke02")
	compromisedRow := run.issuedWithChain(compromised, certsservice.CertsCaGts, big.NewInt(0x88bb02))
	run.clock.Advance(time.Millisecond)
	kept := run.device("k9revoke03")
	keptRow := run.issuedWithChain(kept, certsservice.CertsCaLetsEncrypt, big.NewInt(0x88bb03))

	source := newTestRevocationSource()
	source.set(removedRow.CertId, certsservice.CertsRevocationCauseRemoval)
	source.set(compromisedRow.CertId, certsservice.CertsRevocationCauseKeyCompromise)
	run.service.HoldCa(certsservice.CertsCaLetsEncrypt, run.clock.Now().Add(24*time.Hour))

	report := run.runRevocations(source)
	if !slices.Equal(report.Marked, []sidecar.Id{removedRow.CertId, compromisedRow.CertId}) ||
		!slices.Equal(report.Revoked, []sidecar.Id{removedRow.CertId, compromisedRow.CertId}) ||
		report.WaitingCount != 0 || report.FailedCount != 0 || report.Next != (certsservice.CertsRevocationCursor{}) {
		t.Fatalf("report %+v", report)
	}
	want := []testRevocation{
		{ca: certsservice.CertsCaLetsEncrypt, serial: removedRow.Serial, reason: certsservice.CertsRevocationCessationOfOperation},
		{ca: certsservice.CertsCaGts, serial: compromisedRow.Serial, reason: certsservice.CertsRevocationKeyCompromise},
	}
	if got := run.acme.revocations(); !slices.Equal(got, want) {
		t.Fatalf("revocations %+v", got)
	}
	for _, certId := range []sidecar.Id{removedRow.CertId, compromisedRow.CertId} {
		if state := run.row(certId).State; state != sidecar.TlsCertStateRevoked {
			t.Fatalf("state %s", state)
		}
	}
	if state := run.row(keptRow.CertId).State; state != sidecar.TlsCertStateIssued {
		t.Fatalf("a certificate with no cause: %s", state)
	}
	if kinds := run.hintKinds(removed, removedRow.CertId); !slices.Equal(kinds, []protocol.TlsHintKind{
		protocol.TlsHintKind_TLS_HINT_REVOKED, protocol.TlsHintKind_TLS_HINT_REVOKED,
	}) {
		t.Fatalf("hints %v", kinds)
	}
	if len(run.hints(kept)) != 0 {
		t.Fatal("a kept certificate's device was hinted")
	}
	// the host was shown each certificate's names
	source.stateLock.Lock()
	names := source.names[removedRow.CertId]
	source.stateLock.Unlock()
	if !slices.Equal(names, removed.identifierSet) {
		t.Fatalf("names %v", names)
	}
	// a revoked certificate does not renew
	run.clock.Advance(31 * 24 * time.Hour)
	if renewals := run.runRenewals(); len(renewals.Queued) != 1 || run.row(keptRow.CertId).SuccessorCertId != renewals.Queued[0] {
		t.Fatalf("renewals %+v", renewals)
	}
}

// A row marked by another path, a takedown's or the device's own request, goes to its CA with
// cessationOfOperation and no source; a CA that will not take it leaves the row revoking for the next
// pass; and a marked row whose validity ended is expired, never sent.
func TestCertsRunRevocationsTakesMarkedRows(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9revoke04")
	row := run.issuedWithChain(device, certsservice.CertsCaLetsEncrypt, big.NewInt(0x88bb04))
	run.clock.Advance(time.Millisecond)
	ending := run.issuedWithChain(run.device("k9revoke05"), certsservice.CertsCaLetsEncrypt, big.NewInt(0x88bb05))
	for _, certId := range []sidecar.Id{row.CertId, ending.CertId} {
		if moved, err := run.store.TransitionCert(run.ctx, &certsservice.CertsTransition{
			CertId: certId, From: []sidecar.TlsCertState{sidecar.TlsCertStateIssued}, To: sidecar.TlsCertStateRevoking,
		}); err != nil || !moved {
			t.Fatalf("marking: %v, %v", moved, err)
		}
	}

	run.acme.stateLock.Lock()
	run.acme.revokeErr = errors.New("the CA is down")
	run.acme.stateLock.Unlock()
	report := run.runRevocations(nil)
	if report.FailedCount != 2 || len(report.Revoked) != 0 || run.row(row.CertId).State != sidecar.TlsCertStateRevoking {
		t.Fatalf("report %+v", report)
	}
	run.acme.stateLock.Lock()
	run.acme.revokeErr = nil
	run.acme.stateLock.Unlock()

	// the second certificate ends before the CA is back
	if _, err := run.store.TransitionCert(run.ctx, &certsservice.CertsTransition{
		CertId: ending.CertId, From: []sidecar.TlsCertState{sidecar.TlsCertStateRevoking}, To: sidecar.TlsCertStateRevoking,
		NotAfter: run.clock.Now().Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	run.clock.Advance(time.Second)
	report = run.runRevocations(nil)
	if !slices.Equal(report.Revoked, []sidecar.Id{row.CertId}) || !slices.Equal(report.Expired, []sidecar.Id{ending.CertId}) || len(report.Marked) != 0 {
		t.Fatalf("report %+v", report)
	}
	if got := run.acme.revocations(); len(got) != 1 || got[0].serial != row.Serial || got[0].reason != certsservice.CertsRevocationCessationOfOperation {
		t.Fatalf("revocations %+v", got)
	}
	if kinds := run.hintKinds(device, row.CertId); !slices.Equal(kinds, []protocol.TlsHintKind{protocol.TlsHintKind_TLS_HINT_REVOKED}) {
		t.Fatalf("hints %v", kinds)
	}
}

// A marked row with no chain waits, since a CA revokes only a certificate it is shown; and a host with
// no ACME client still marks what the sweep finds, and takes nothing to a CA.
func TestCertsRunRevocationsWaitsWithNoChainOrNoCa(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9revoke06")
	certId := run.accept(device)
	run.runOrders()
	source := newTestRevocationSource()
	source.set(certId, certsservice.CertsRevocationCauseDeletion)
	report := run.runRevocations(source)
	if !slices.Equal(report.Marked, []sidecar.Id{certId}) || report.WaitingCount != 1 || len(report.Revoked) != 0 {
		t.Fatalf("report %+v", report)
	}
	if state := run.row(certId).State; state != sidecar.TlsCertStateRevoking {
		t.Fatalf("state %s", state)
	}
	if got := run.acme.revocations(); len(got) != 0 {
		t.Fatalf("revocations %+v", got)
	}
	// it is not marked, or hinted, a second time
	hintCount := len(run.hints(device))
	if again := run.runRevocations(source); len(again.Marked) != 0 || again.WaitingCount != 1 || len(run.hints(device)) != hintCount {
		t.Fatalf("a second pass %+v", again)
	}

	closed := newTestCerts(t, nil)
	closedRun := &testRun{testCerts: closed, acme: newTestRunAcme(t, closed.clock)}
	closedDevice := closedRun.device("k9revoke07")
	closedRow := closedRun.issuedWithChain(closedDevice, certsservice.CertsCaLetsEncrypt, big.NewInt(0x88bb07))
	closedSource := newTestRevocationSource()
	closedSource.set(closedRow.CertId, certsservice.CertsRevocationCauseAliasRetired)
	closedReport, err := closed.service.RunRevocations(closed.ctx, closedSource, nil)
	if err != nil || !closedReport.Unavailable || !slices.Equal(closedReport.Marked, []sidecar.Id{closedRow.CertId}) ||
		closedReport.WaitingCount != 1 || len(closedReport.Revoked) != 0 {
		t.Fatalf("report %+v, %v", closedReport, err)
	}
	if state := closed.row(closedRow.CertId).State; state != sidecar.TlsCertStateRevoking {
		t.Fatalf("state %s", state)
	}
}

// A revocation pass reads at most its batch of each kind and says where the next starts; a source that
// cannot answer ends the pass with nothing marked.
func TestCertsRunRevocationsPagesAndStopsOnItsSource(t *testing.T) {
	settings := testSettings()
	settings.RevocationBatchCount = 1
	run := newTestRun(t, settings)
	first := run.issuedWithChain(run.device("k9revoke08"), certsservice.CertsCaLetsEncrypt, big.NewInt(0x88bb08))
	run.clock.Advance(time.Millisecond)
	second := run.issuedWithChain(run.device("k9revoke09"), certsservice.CertsCaLetsEncrypt, big.NewInt(0x88bb09))
	source := newTestRevocationSource()
	source.set(second.CertId, certsservice.CertsRevocationCauseRemoval)

	source.err = errors.New("postgres is away")
	if report, err := run.service.RunRevocations(run.ctx, source, nil); err == nil || len(report.Marked) != 0 {
		t.Fatalf("report %+v, %v", report, err)
	}
	source.err = nil

	report := run.runRevocations(source)
	if len(report.Marked) != 0 || report.Next.AfterIssuedCertId != first.CertId {
		t.Fatalf("report %+v", report)
	}
	report, err := run.service.RunRevocations(run.ctx, source, &report.Next)
	if err != nil || !slices.Equal(report.Marked, []sidecar.Id{second.CertId}) || !slices.Equal(report.Revoked, []sidecar.Id{second.CertId}) {
		t.Fatalf("the next pass %+v, %v", report, err)
	}
	if state := run.row(first.CertId).State; state != sidecar.TlsCertStateIssued {
		t.Fatalf("state %s", state)
	}
}

// A failed hint is counted and stops nothing: the order still issues.
func TestCertsRunOrdersCountsALostHint(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9runord10")
	certId := run.accept(device)
	if _, err := run.host.Redis.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "push.Hint", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	report := run.runOrders()
	if !slices.Equal(report.Issued, []sidecar.Id{certId}) {
		t.Fatalf("report %+v", report)
	}
	if report.Hints.Sent != 1 || report.Hints.Failed != 1 {
		t.Fatalf("hint counts %+v", report.Hints)
	}
	if kinds := run.hintKinds(device, certId); !slices.Equal(kinds, []protocol.TlsHintKind{protocol.TlsHintKind_TLS_HINT_ISSUED}) {
		t.Fatalf("hints %v", kinds)
	}
}
