//go:build !sidecar_http && !ios_extension

// The ordering desktop's waits under its claim (DESIGN-DETAILS 17.2.6, 17.2.7, 17.2.9): one custom row of one account,
// ordered by DNS-01, with two desktops that run the orderer's passes against a fake of the custom routes that keeps the
// account's lock as api does, a fake CA whose one order moves on a clock the desktops share, and public DNS answering
// what the routes wrote. Each wait passes at once, moving the shared clock on by it, so a desktop held past its lease
// is a jump of the clock, and a hook at each wait lets the other desktop run between. Names are under .example, keys
// generated.

package sidecar

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What a request that is never answered returns: no reply, an outcome unknown.
var errTlsCustomLeaseNoAnswer = errors.New("the request timed out with no answer")

// The desktops' shared clock. Each wait passes at once, moving the time on by it; then the observers see the new time,
// and onWait runs on the waiting desktop's goroutine.
type tlsCustomLeaseClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     map[string][]time.Duration
	onWait    func(desktop string)
	observers []func(now time.Time)
}

func (self *tlsCustomLeaseClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Moves the time on by timeout, as desktop's wait unless desktop is "", and tells the observers.
func (self *tlsCustomLeaseClock) advance(desktop string, timeout time.Duration) {
	var now time.Time
	var observers []func(now time.Time)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if desktop != "" {
			self.waits[desktop] = append(self.waits[desktop], timeout)
		}
		self.now = self.now.Add(max(timeout, 0))
		now = self.now
		observers = slices.Clone(self.observers)
	}()
	for _, observe := range observers {
		observe(now)
	}
}

// Runs onWait at each wait of a desktop, once the wait's time has passed.
func (self *tlsCustomLeaseClock) setOnWait(onWait func(desktop string)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.onWait = onWait
}

// One desktop's view of the shared clock.
type tlsCustomDesktopClock struct {
	clock   *tlsCustomLeaseClock
	desktop string
}

func (self *tlsCustomDesktopClock) Now() time.Time {
	return self.clock.Now()
}

func (self *tlsCustomDesktopClock) After(timeout time.Duration) <-chan time.Time {
	self.clock.advance(self.desktop, timeout)
	onWait := func() func(desktop string) {
		self.clock.stateLock.Lock()
		defer self.clock.stateLock.Unlock()
		return self.clock.onWait
	}()
	if onWait != nil {
		onWait(self.desktop)
	}
	fired := make(chan time.Time, 1)
	fired <- self.clock.Now()
	return fired
}

func (self *tlsCustomDesktopClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// One request a desktop made of the custom routes or of the CA, in the order made.
type tlsCustomLeaseCall struct {
	desktop string
	// the route (work, claim, progress <event>, register, challenge, challenge-status) or the CA's request (acme
	// new-order, acme order, acme authorization, acme challenge, acme finalize, acme certificate, acme deactivate, acme
	// revoke)
	name string
	at   time.Time
	// a claim's answer, or the claim a progress event, register or capture named
	claimSeq uint64
	// the refusal's reason, "unanswered" for no answer, "" for none
	refusal string
}

// Every request of the world, in order.
type tlsCustomLeaseLog struct {
	stateLock sync.Mutex
	calls     []*tlsCustomLeaseCall
}

func (self *tlsCustomLeaseLog) add(call *tlsCustomLeaseCall) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
}

// How many requests there were so far.
func (self *tlsCustomLeaseLog) mark() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.calls)
}

// The requests of desktop from index on, named name or any for "".
func (self *tlsCustomLeaseLog) since(index int, desktop string, name string) []*tlsCustomLeaseCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := []*tlsCustomLeaseCall{}
	for _, call := range self.calls[index:] {
		if call.desktop == desktop && (name == "" || call.name == name) {
			calls = append(calls, call)
		}
	}
	return calls
}

// How many requests desktop made named name, any desktop's for "".
func (self *tlsCustomLeaseLog) count(desktop string, name string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, call := range self.calls {
		if (desktop == "" || call.desktop == desktop) && call.name == name {
			count += 1
		}
	}
	return count
}

// The custom routes for one account and its one row, as api keeps them (17.2.5, 17.2.6): a claim takes the lock while
// it is free or its lease has run out, raising the claim sequence, renews it for its holder at the same sequence, and
// is refused locked otherwise; progress, register and the challenge's capture check the holder and the sequence, never
// the lease, as api's do. One receipt a claim: a capture writes its digest once, at the next serial, and the edges
// serve a write readyAfter after it.
type tlsCustomLeaseServer struct {
	stateLock  sync.Mutex
	clock      *tlsCustomLeaseClock
	log        *tlsCustomLeaseLog
	lease      time.Duration
	readyAfter time.Duration
	account    *TlsCustomAccount
	row        *TlsCertRecord
	orderUrl   string

	lockSeq     uint64
	holder      string
	lockCertId  Id
	lockPurpose string
	lockUntil   time.Time
	// the claims whose lease ran out while their holder still held the lock
	lapsed []uint64

	receipts  map[uint64]*tlsCustomTestReceipt
	serial    uint64
	writes    []tlsCustomTestWrite
	writeTime time.Time
	// the claim the row was registered under, and by whom
	issuedClaimSeq uint64
	issuedBy       string
	// whether a desktop's request at a route goes unanswered, unmade; nil for never
	unanswered func(desktop string, route string) bool
}

// Records a lapse when the time passes the holder's lease.
func (self *tlsCustomLeaseServer) observe(now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.holder != "" && !now.Before(self.lockUntil) && !slices.Contains(self.lapsed, self.lockSeq) {
		self.lapsed = append(self.lapsed, self.lockSeq)
	}
}

// The request's call, logged; and no answer when the script says so.
func (self *tlsCustomLeaseServer) call(desktop string, route string, claimSeq uint64) (*tlsCustomLeaseCall, error) {
	call := &tlsCustomLeaseCall{desktop: desktop, name: route, at: self.clock.Now(), claimSeq: claimSeq}
	self.log.add(call)
	if self.unanswered != nil && self.unanswered(desktop, route) {
		call.refusal = "unanswered"
		return call, errTlsCustomLeaseNoAnswer
	}
	return call, nil
}

// A refusal, logged on its call.
func (self *tlsCustomLeaseServer) refuse(call *tlsCustomLeaseCall, status int, reason string) error {
	call.refusal = reason
	return &TlsCustomError{Status: status, Refusal: TlsCustomRefusal{Reason: reason}}
}

// Frees the lock; a row with no order recorded goes back to the queue.
func (self *tlsCustomLeaseServer) freeWithLock() {
	self.holder = ""
	self.lockUntil = time.Time{}
	if self.row.State == TlsCertStateCustomOrdering && self.orderUrl == "" {
		self.row.State = TlsCertStateCustomQueued
	}
}

// Whether desktop holds the lock under claimSeq for certId, as api's heldBy reads it: never the lease.
func (self *tlsCustomLeaseServer) heldByWithLock(desktop string, claimSeq uint64, certId Id) bool {
	return self.holder == desktop && self.lockSeq == claimSeq && claimSeq != 0 && self.lockCertId == certId
}

// The row as an answer carries it.
func (self *tlsCustomLeaseServer) recordWithLock() *TlsCertRecord {
	record := *self.row
	return &record
}

// The removal of the row's device under its recorded order (17.2.4): the row to custom_revoking, and the lock freed
// where it names the row.
func (self *tlsCustomLeaseServer) remove() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.row.State == TlsCertStateCustomOrdering && self.orderUrl != "" {
		self.row.State = TlsCertStateCustomRevoking
	}
	if self.lockCertId == self.row.CertId {
		self.holder = ""
		self.lockUntil = time.Time{}
	}
}

// The written values the acme name's TXT holds.
func (self *tlsCustomLeaseServer) txt() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	values := []string{}
	for _, write := range self.writes {
		values = append(values, write.value)
	}
	return values
}

// The custom routes as desktop calls them.
type tlsCustomLeaseApi struct {
	server  *tlsCustomLeaseServer
	desktop string
}

func (self *tlsCustomLeaseApi) Work(ctx context.Context) (*TlsCertsResult, error) {
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	if _, err := server.call(self.desktop, "work", 0); err != nil {
		return nil, err
	}
	account := *server.account
	work := &TlsCertsResult{Accounts: []*TlsCustomAccount{&account}}
	if server.row.State == TlsCertStateCustomQueued || server.row.State == TlsCertStateCustomOrdering {
		work.QueuedCsrs = append(work.QueuedCsrs, server.recordWithLock())
	}
	return work, nil
}

func (self *tlsCustomLeaseApi) Claim(ctx context.Context, args *TlsCustomClaimArgs) (*TlsCustomClaimResult, error) {
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	call, err := server.call(self.desktop, "claim", 0)
	if err != nil {
		return nil, err
	}
	now := server.clock.Now()
	leaseMs := uint32(server.lease.Milliseconds())
	held := server.holder != "" && now.Before(server.lockUntil)
	if held && server.holder == self.desktop && server.lockPurpose == args.Purpose && server.lockCertId == args.CertId {
		// a renewal
		server.lockUntil = now.Add(server.lease)
		call.claimSeq = server.lockSeq
		return &TlsCustomClaimResult{ClaimSeq: server.lockSeq, LeaseMs: leaseMs, Record: server.recordWithLock(), OrderUrl: server.orderUrl}, nil
	}
	if held {
		return nil, server.refuse(call, http.StatusConflict, TlsCustomRefusalLocked)
	}
	if args.CertId != server.row.CertId || (server.row.State != TlsCertStateCustomQueued && server.row.State != TlsCertStateCustomOrdering) {
		return nil, server.refuse(call, http.StatusConflict, TlsCustomRefusalState)
	}
	server.row.State = TlsCertStateCustomOrdering
	server.lockSeq += 1
	server.holder = self.desktop
	server.lockPurpose = args.Purpose
	server.lockCertId = args.CertId
	server.lockUntil = now.Add(server.lease)
	call.claimSeq = server.lockSeq
	return &TlsCustomClaimResult{
		ClaimSeq: server.lockSeq,
		LeaseMs:  leaseMs,
		Record:   server.recordWithLock(),
		OrderUrl: server.orderUrl,
		MayOrder: server.orderUrl == "",
	}, nil
}

func (self *tlsCustomLeaseApi) Progress(ctx context.Context, args *TlsCustomProgressArgs) (*TlsCustomClaimResult, error) {
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	call, err := server.call(self.desktop, "progress "+args.Event, args.ClaimSeq)
	if err != nil {
		return nil, err
	}
	if !server.heldByWithLock(self.desktop, args.ClaimSeq, args.CertId) {
		return nil, server.refuse(call, http.StatusConflict, TlsCustomRefusalClaim)
	}
	switch args.Event {
	case TlsCustomEventOrderRecorded:
		if server.orderUrl != "" {
			return nil, server.refuse(call, http.StatusConflict, TlsCustomRefusalState)
		}
		server.orderUrl = args.OrderUrl
	case TlsCustomEventRelease, TlsCustomEventRateLimited:
		server.freeWithLock()
	case TlsCustomEventOrderInvalid:
		// no other order granted here: the row waits in the queue
		server.orderUrl = ""
		server.freeWithLock()
		return nil, server.refuse(call, http.StatusTooManyRequests, TlsCustomRefusalBudget)
	case TlsCustomEventFailed:
		if server.orderUrl == "" {
			server.row.State = TlsCertStateFailed
		} else {
			server.row.State = TlsCertStateCustomRevoking
		}
		server.freeWithLock()
	}
	return &TlsCustomClaimResult{}, nil
}

func (self *tlsCustomLeaseApi) Register(ctx context.Context, args *TlsCertRegisterArgs) error {
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	call, err := server.call(self.desktop, "register", args.ClaimSeq)
	if err != nil {
		return err
	}
	if !server.heldByWithLock(self.desktop, args.ClaimSeq, args.CertId) {
		return server.refuse(call, http.StatusConflict, TlsCustomRefusalClaim)
	}
	if server.row.State != TlsCertStateCustomOrdering {
		return server.refuse(call, http.StatusConflict, TlsCustomRefusalState)
	}
	server.row.State = TlsCertStateCustomIssued
	server.row.Chain = args.Chain
	server.issuedClaimSeq = args.ClaimSeq
	server.issuedBy = self.desktop
	server.freeWithLock()
	return nil
}

func (self *tlsCustomLeaseApi) Account(ctx context.Context, args *TlsCustomAccountArgs) (*TlsCustomAccount, error) {
	return nil, errors.New("no account op in this world")
}

func (self *tlsCustomLeaseApi) Challenge(ctx context.Context, args *TlsCustomChallengeArgs) (*TlsCustomChallengeResult, error) {
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	call, err := server.call(self.desktop, "challenge", 0)
	if err != nil {
		return nil, err
	}
	// the caller's claim: the lock taken for an order, its row ordering under it; never the lease
	if server.holder != self.desktop || server.lockPurpose != TlsCustomPurposeOrder || server.row.State != TlsCertStateCustomOrdering {
		return nil, server.refuse(call, http.StatusConflict, TlsCustomRefusalClaim)
	}
	call.claimSeq = server.lockSeq
	receipt := server.receipts[server.lockSeq]
	if receipt == nil || receipt.value != args.Value {
		server.serial += 1
		receipt = &tlsCustomTestReceipt{value: args.Value, serial: server.serial}
		server.receipts[server.lockSeq] = receipt
		server.writes = append(server.writes, tlsCustomTestWrite{claimSeq: server.lockSeq, value: args.Value, serial: server.serial})
		server.writeTime = server.clock.Now()
	}
	return &TlsCustomChallengeResult{ChallengeId: receipt.serial}, nil
}

func (self *tlsCustomLeaseApi) ChallengeStatus(ctx context.Context, challengeId uint64) (*TlsCustomChallengeResult, error) {
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	if _, err := server.call(self.desktop, "challenge-status", 0); err != nil {
		return nil, err
	}
	readiness := TlsCustomReadinessReady
	if server.clock.Now().Before(server.writeTime.Add(server.readyAfter)) {
		readiness = "waiting"
	}
	return &TlsCustomChallengeResult{ChallengeId: challengeId, Readiness: readiness}, nil
}

// Public DNS as the customer delegated it: _acme-challenge to the account's acme name, whose TXT the routes wrote.
type tlsCustomLeaseResolver struct {
	server *tlsCustomLeaseServer
}

func (self *tlsCustomLeaseResolver) LookupCname(ctx context.Context, name string) (string, error) {
	return self.server.account.AcmeName + ".", nil
}

func (self *tlsCustomLeaseResolver) LookupTxt(ctx context.Context, name string) ([]string, error) {
	return self.server.txt(), nil
}

// The verified view of both desktops: the row's device admitted under its identity key and granted.
type tlsCustomLeaseDevices struct {
	sidecarId         Id
	identityPublicKey []byte
}

func (self *tlsCustomLeaseDevices) Device(sidecarId Id, ownerLabel string) ([]byte, bool) {
	if sidecarId != self.sidecarId {
		return nil, false
	}
	return self.identityPublicKey, true
}

func (self *tlsCustomLeaseDevices) Holds443(ownerLabel string) bool { return false }
func (self *tlsCustomLeaseDevices) SidecarId() Id                   { return Id{} }
func (self *tlsCustomLeaseDevices) NetworkId() Id                   { return testNetworkId }

// The CA's one order for the row's host, moving on the shared clock: pending until its challenge is answered and
// validateAfter has passed, ready until finalized, processing until issueAfter has passed since, then valid. A negative
// duration never passes. The first finalize may take and lose its answer; reads of the order go unanswered for
// readOutage from the finalize, negative for ever; the first certificateOutages downloads go unanswered.
type tlsCustomLeaseCa struct {
	stateLock sync.Mutex
	clock     *tlsCustomLeaseClock
	log       *tlsCustomLeaseLog
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	caDer     []byte

	validateAfter      time.Duration
	issueAfter         time.Duration
	finalizeLost       bool
	readOutage         time.Duration
	certificateOutages int

	ordered       bool
	challengeTime time.Time
	finalizeTime  time.Time
	chain         [][]byte
}

const (
	tlsCustomLeaseOrderUrl         = "https://ca.example/order/1"
	tlsCustomLeaseAuthorizationUrl = "https://ca.example/authz/1"
	tlsCustomLeaseChallengeUrl     = "https://ca.example/chall/1"
	tlsCustomLeaseCertificateUrl   = "https://ca.example/cert/1"
)

// When the challenge was answered and the order finalized, zero until each was.
func (self *tlsCustomLeaseCa) times() (time.Time, time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.challengeTime, self.finalizeTime
}

// The order's status now.
func (self *tlsCustomLeaseCa) statusWithLock() string {
	now := self.clock.Now()
	passed := func(from time.Time, after time.Duration) bool {
		return !from.IsZero() && 0 <= after && !now.Before(from.Add(after))
	}
	switch {
	case !passed(self.challengeTime, self.validateAfter):
		return TlsAcmeStatusPending
	case self.finalizeTime.IsZero():
		return TlsAcmeStatusReady
	case !passed(self.finalizeTime, self.issueAfter):
		return TlsAcmeStatusProcessing
	}
	return TlsAcmeStatusValid
}

// The order as the CA answers it now.
func (self *tlsCustomLeaseCa) orderWithLock() *TlsAcmeOrder {
	order := &TlsAcmeOrder{Url: tlsCustomLeaseOrderUrl, Status: self.statusWithLock(), Authorizations: []string{tlsCustomLeaseAuthorizationUrl}, Finalize: tlsCustomLeaseOrderUrl + "/finalize"}
	if order.Status == TlsAcmeStatusValid {
		order.Certificate = tlsCustomLeaseCertificateUrl
	}
	return order
}

// The CA as desktop reaches it.
type tlsCustomLeaseCaClient struct {
	tlsCustomUnreachedCa
	ca      *tlsCustomLeaseCa
	desktop string
}

// The request's call, logged.
func (self *tlsCustomLeaseCaClient) call(name string) *tlsCustomLeaseCall {
	call := &tlsCustomLeaseCall{desktop: self.desktop, name: "acme " + name, at: self.ca.clock.Now()}
	self.ca.log.add(call)
	return call
}

func (self *tlsCustomLeaseCaClient) NewOrder(ctx context.Context, key crypto.Signer, accountUri string, name string, profile string, replacesLeaf []byte) (*TlsAcmeOrder, error) {
	ca := self.ca
	ca.stateLock.Lock()
	defer ca.stateLock.Unlock()
	self.call("new-order")
	ca.ordered = true
	return ca.orderWithLock(), nil
}

func (self *tlsCustomLeaseCaClient) Order(ctx context.Context, key crypto.Signer, accountUri string, orderUrl string) (*TlsAcmeOrder, error) {
	ca := self.ca
	ca.stateLock.Lock()
	defer ca.stateLock.Unlock()
	call := self.call("order")
	if !ca.ordered || orderUrl != tlsCustomLeaseOrderUrl {
		return nil, ErrTlsAcmeGone
	}
	if !ca.finalizeTime.IsZero() && ca.readOutage != 0 && (ca.readOutage < 0 || ca.clock.Now().Before(ca.finalizeTime.Add(ca.readOutage))) {
		call.refusal = "unanswered"
		return nil, errTlsCustomLeaseNoAnswer
	}
	return ca.orderWithLock(), nil
}

func (self *tlsCustomLeaseCaClient) Authorization(ctx context.Context, key crypto.Signer, accountUri string, url string) (*TlsAcmeAuthorization, error) {
	ca := self.ca
	ca.stateLock.Lock()
	defer ca.stateLock.Unlock()
	self.call("authorization")
	status := TlsAcmeStatusValid
	if ca.statusWithLock() == TlsAcmeStatusPending {
		status = TlsAcmeStatusPending
	}
	return &TlsAcmeAuthorization{
		Url:        tlsCustomLeaseAuthorizationUrl,
		Status:     status,
		Challenges: []*TlsAcmeChallenge{{Type: TlsAcmeChallengeDns, Url: tlsCustomLeaseChallengeUrl, Token: "token-1", Status: status}},
	}, nil
}

func (self *tlsCustomLeaseCaClient) KeyAuthorization(key crypto.Signer, token string) (string, error) {
	return token + ".thumbprint", nil
}

func (self *tlsCustomLeaseCaClient) Challenge(ctx context.Context, key crypto.Signer, accountUri string, url string) error {
	ca := self.ca
	ca.stateLock.Lock()
	defer ca.stateLock.Unlock()
	self.call("challenge")
	if ca.challengeTime.IsZero() {
		ca.challengeTime = ca.clock.Now()
	}
	return nil
}

func (self *tlsCustomLeaseCaClient) Finalize(ctx context.Context, key crypto.Signer, accountUri string, order *TlsAcmeOrder, csrDer []byte) (*TlsAcmeOrder, error) {
	ca := self.ca
	ca.stateLock.Lock()
	defer ca.stateLock.Unlock()
	call := self.call("finalize")
	if ca.statusWithLock() != TlsAcmeStatusReady {
		call.refusal = TlsAcmeProblemOrderNotReady
		return nil, &TlsAcmeProblem{Type: TlsAcmeProblemOrderNotReady, Status: http.StatusForbidden}
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return nil, &TlsAcmeProblem{Type: TlsAcmeProblemBadCsr, Status: http.StatusBadRequest}
	}
	now := ca.clock.Now()
	leafDer, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), DNSNames: csr.DNSNames}, ca.caCert, csr.PublicKey, ca.caKey)
	if err != nil {
		return nil, err
	}
	ca.chain = [][]byte{leafDer, ca.caDer}
	ca.finalizeTime = now
	if ca.finalizeLost {
		call.refusal = "unanswered"
		return nil, errTlsCustomLeaseNoAnswer
	}
	return ca.orderWithLock(), nil
}

func (self *tlsCustomLeaseCaClient) Certificate(ctx context.Context, key crypto.Signer, accountUri string, url string) ([][]byte, error) {
	ca := self.ca
	ca.stateLock.Lock()
	defer ca.stateLock.Unlock()
	call := self.call("certificate")
	if 0 < ca.certificateOutages {
		ca.certificateOutages -= 1
		call.refusal = "unanswered"
		return nil, errTlsCustomLeaseNoAnswer
	}
	if ca.statusWithLock() != TlsAcmeStatusValid {
		return nil, &TlsAcmeProblem{Type: "malformed", Status: http.StatusNotFound}
	}
	return ca.chain, nil
}

func (self *tlsCustomLeaseCaClient) RenewalInfo(ctx context.Context, leaf []byte) (time.Time, time.Time, error) {
	return time.Time{}, time.Time{}, errors.New("no renewal info")
}

func (self *tlsCustomLeaseCaClient) DeactivateAuthorization(ctx context.Context, key crypto.Signer, accountUri string, url string) error {
	self.call("deactivate")
	return nil
}

func (self *tlsCustomLeaseCaClient) Revoke(ctx context.Context, key crypto.Signer, accountUri string, leaf []byte, reason int) error {
	self.call("revoke")
	return nil
}

// Two desktops, a and b, ordering one row of one account on the routes, the CA and the clock they share.
type tlsCustomLeaseWorld struct {
	clock    *tlsCustomLeaseClock
	log      *tlsCustomLeaseLog
	server   *tlsCustomLeaseServer
	ca       *tlsCustomLeaseCa
	desktops map[string]*TlsCustomDomainOrderer
	certId   Id
}

// The world under a lease of leaseMs, each desktop's settings nil taking the defaults, the CA's order moving as
// setCa sets it.
func newTlsCustomLeaseWorld(t *testing.T, leaseMs uint32, settings *TlsCustomSettings, setCa func(ca *tlsCustomLeaseCa)) *tlsCustomLeaseWorld {
	t.Helper()
	fail := func(err error) {
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
	}
	host := "www.customer.example"
	roots := []string{"sidecar.example"}
	clock := &tlsCustomLeaseClock{now: time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC), waits: map[string][]time.Duration{}}
	log := &tlsCustomLeaseLog{}

	// the account, and its key file in its secret repo
	accountDer, err := NewTlsCustomAccountKey()
	fail(err)
	accountKey, err := tlsCustomParseKey(accountDer)
	fail(err)
	keyRepoId := NewId()
	file := &TlsCustomKeyFile{Format: tlsCustomKeyFileFormat, Domain: "customer.example", Ca: "letsencrypt", AccountUri: "https://ca.example/acct/1", KeySeq: 1, Key: accountDer}
	fileData, err := file.Marshal()
	fail(err)
	account := &TlsCustomAccount{
		Domain:        "customer.example",
		Ca:            "letsencrypt",
		AccountUri:    file.AccountUri,
		KeySeq:        1,
		KeyThumbprint: TlsCustomKeyThumbprint(&accountKey.PublicKey),
		KeyRepoId:     keyRepoId,
		AcmeName:      "a1b2c3.acme.sidecar.example",
	}

	// the device's CSR for the host and its attestation
	seed := sha256.Sum256([]byte("lease device identity"))
	sidecarId := tlsCertTestId("lease device")
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fail(err)
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, deviceKey)
	fail(err)
	csr, err := x509.ParseCertificateRequest(csrDer)
	fail(err)
	set, err := TlsCustomIdentifierSet(host, roots)
	fail(err)
	setSha256, err := TlsIdentifierSetHash(set)
	fail(err)
	spkiSha256 := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	attestation, err := SignTlsKeyAttestation(&protocol.TlsKeyAttestation{
		NetworkId:           testNetworkId[:],
		SidecarId:           sidecarId[:],
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: setSha256[:],
		IssueTimeMillis:     uint64(clock.now.UnixMilli()),
	}, testTlsSign(seed[:], sidecarId[:]))
	fail(err)
	row := &TlsCertRecord{
		CertId:       NewId(),
		NetworkId:    testNetworkId,
		SidecarId:    sidecarId,
		Attestation:  attestation,
		Csr:          csrDer,
		State:        TlsCertStateCustomQueued,
		CustomHost:   host,
		CustomDomain: "customer.example",
		Owner:        "shop",
	}

	// the CA's own root
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fail(err)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lease test ca"}, NotBefore: clock.now.Add(-time.Hour), NotAfter: clock.now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	fail(err)
	caCert, err := x509.ParseCertificate(caDer)
	fail(err)
	ca := &tlsCustomLeaseCa{clock: clock, log: log, caKey: caKey, caCert: caCert, caDer: caDer}
	if setCa != nil {
		setCa(ca)
	}

	server := &tlsCustomLeaseServer{
		clock:    clock,
		log:      log,
		lease:    time.Duration(leaseMs) * time.Millisecond,
		account:  account,
		row:      row,
		receipts: map[uint64]*tlsCustomTestReceipt{},
	}
	clock.observers = append(clock.observers, server.observe)

	world := &tlsCustomLeaseWorld{clock: clock, log: log, server: server, ca: ca, desktops: map[string]*TlsCustomDomainOrderer{}, certId: row.CertId}
	for _, desktop := range []string{"a", "b"} {
		orderer, err := NewTlsCustomDomainOrderer(&TlsCustomDomainOrdererDeps{
			Api:      &tlsCustomLeaseApi{server: server, desktop: desktop},
			Acme:     &tlsCustomLeaseCaClient{ca: ca, desktop: desktop},
			Resolver: &tlsCustomLeaseResolver{server: server},
			Devices:  &tlsCustomLeaseDevices{sidecarId: sidecarId, identityPublicKey: testTlsIdentityPublicKey(seed[:])},
			Keys:     &tlsCustomTestKeys{files: map[Id][]byte{keyRepoId: fileData}, locals: map[string][]byte{}},
			Roots:    roots,
			Clock:    &tlsCustomDesktopClock{clock: clock, desktop: desktop},
		}, settings)
		fail(err)
		world.desktops[desktop] = orderer
	}
	return world
}

// One pass of desktop.
func (self *tlsCustomLeaseWorld) pass(desktop string) *TlsCustomPassReport {
	report, err := self.desktops[desktop].RunOnce(context.Background())
	if err != nil {
		return &TlsCustomPassReport{}
	}
	return report
}

// The longest stretch desktop held the lock unrenewed: between its claims the server answered, and from the last of
// them to its last request.
func (self *tlsCustomLeaseWorld) longestUnrenewed(desktop string) time.Duration {
	times := []time.Time{}
	calls := self.log.since(0, desktop, "")
	for _, call := range calls {
		if call.name == "claim" && call.refusal == "" {
			times = append(times, call.at)
		}
	}
	if len(times) == 0 {
		return 0
	}
	times = append(times, calls[len(calls)-1].at)
	longest := time.Duration(0)
	for index := 1; index < len(times); index += 1 {
		longest = max(longest, times[index].Sub(times[index-1]))
	}
	return longest
}

// The routes' state at one moment.
type tlsCustomLeaseSnapshot struct {
	// the lock's holder, "" while free
	holder         string
	state          TlsCertState
	orderUrl       string
	issuedBy       string
	issuedClaimSeq uint64
	lapsed         []uint64
	writes         []tlsCustomTestWrite
}

// The routes' lock and row now.
func (self *tlsCustomLeaseWorld) snapshot() *tlsCustomLeaseSnapshot {
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	return &tlsCustomLeaseSnapshot{
		holder:         server.holder,
		state:          server.row.State,
		orderUrl:       server.orderUrl,
		issuedBy:       server.issuedBy,
		issuedClaimSeq: server.issuedClaimSeq,
		lapsed:         slices.Clone(server.lapsed),
		writes:         slices.Clone(server.writes),
	}
}

// One of the waits a holder spends under its claim between requests to the CA (17.2.7 step 5, 17.2.9 step 5).
type tlsCustomLeaseWait struct {
	name string
	// holds the order in the wait for hold, negative for ever
	set func(ca *tlsCustomLeaseCa, hold time.Duration)
	// when the wait began, zero before
	began func(ca *tlsCustomLeaseCa) time.Time
}

// The three: the authorization polled after the CA's challenge, the order polled while processing, and the order read
// again after a finalize whose answer was lost, until the CA answers.
func tlsCustomLeaseWaits() []*tlsCustomLeaseWait {
	challenged := func(ca *tlsCustomLeaseCa) time.Time {
		challengeTime, _ := ca.times()
		return challengeTime
	}
	finalized := func(ca *tlsCustomLeaseCa) time.Time {
		_, finalizeTime := ca.times()
		return finalizeTime
	}
	return []*tlsCustomLeaseWait{
		{
			name:  "the authorization poll",
			set:   func(ca *tlsCustomLeaseCa, hold time.Duration) { ca.validateAfter = hold },
			began: challenged,
		},
		{
			name:  "the processing poll",
			set:   func(ca *tlsCustomLeaseCa, hold time.Duration) { ca.issueAfter = hold },
			began: finalized,
		},
		{
			name: "finalize's re-reads",
			set: func(ca *tlsCustomLeaseCa, hold time.Duration) {
				ca.finalizeLost = true
				ca.readOutage = hold
			},
			began: finalized,
		},
	}
}

// Each wait held a minute under a 30 s lease renews the claim every third of it, so the other desktop's poll 40 s in
// is refused locked and the first desktop registers under its first claim: one DNS write, one newOrder, one finalize,
// no lapse and no release.
func TestTlsCustomOrdererKeepsItsClaimThroughEachWait(t *testing.T) {
	for _, wait := range tlsCustomLeaseWaits() {
		world := newTlsCustomLeaseWorld(t, 30_000, nil, func(ca *tlsCustomLeaseCa) {
			wait.set(ca, time.Minute)
		})
		var other *TlsCustomPassReport
		otherMark := 0
		world.clock.setOnWait(func(desktop string) {
			began := wait.began(world.ca)
			if desktop != "a" || other != nil || began.IsZero() || world.clock.Now().Before(began.Add(40*time.Second)) {
				return
			}
			otherMark = world.log.mark()
			other = world.pass("b")
		})
		report := world.pass("a")
		if !slices.Equal(report.Issued, []Id{world.certId}) {
			t.Errorf("%s: a issued %v", wait.name, report.Issued)
			continue
		}
		if other == nil || 0 < len(other.Worked) {
			t.Errorf("%s: b's pass during the wait: %+v", wait.name, other)
			continue
		}
		if claims := world.log.since(otherMark, "b", "claim"); len(claims) != 1 || claims[0].refusal != TlsCustomRefusalLocked {
			t.Errorf("%s: b's claims %+v", wait.name, claims)
		}
		snapshot := world.snapshot()
		if snapshot.state != TlsCertStateCustomIssued || snapshot.issuedBy != "a" || snapshot.issuedClaimSeq != 1 || 0 < len(snapshot.lapsed) {
			t.Errorf("%s: %+v", wait.name, snapshot)
		}
		if longest := world.longestUnrenewed("a"); 10*time.Second < longest {
			t.Errorf("%s: a held the lock %v unrenewed", wait.name, longest)
		}
		for _, claim := range world.log.since(0, "a", "claim") {
			if claim.claimSeq != 1 {
				t.Errorf("%s: a's claim answered %d", wait.name, claim.claimSeq)
			}
		}
		if len(snapshot.writes) != 1 || world.log.count("", "acme new-order") != 1 || world.log.count("", "acme finalize") != 1 || world.log.count("", "acme challenge") != 1 {
			t.Errorf("%s: %d writes, %d newOrders, %d finalizes, %d challenges", wait.name, len(snapshot.writes), world.log.count("", "acme new-order"), world.log.count("", "acme finalize"), world.log.count("", "acme challenge"))
		}
		if released := world.log.count("a", "progress "+TlsCustomEventRelease); released != 0 {
			t.Errorf("%s: a released %d times", wait.name, released)
		}
	}
}

// A lapse that does happen hands the order over cleanly: the first desktop, held 4 s into each wait for 90 s, past its
// lease and the CA's minute, finds its hold lost when it wakes and sends nothing more, to the routes or the CA; the
// other desktop's next claim resumes the recorded order and registers under its own claim, with no newOrder, no
// second DNS write and one finalize in all.
func TestTlsCustomOrdererHandsALapsedOrderOverCleanly(t *testing.T) {
	for _, wait := range tlsCustomLeaseWaits() {
		world := newTlsCustomLeaseWorld(t, 30_000, nil, func(ca *tlsCustomLeaseCa) {
			wait.set(ca, time.Minute)
		})
		stallMark := -1
		var other *TlsCustomPassReport
		world.clock.setOnWait(func(desktop string) {
			began := wait.began(world.ca)
			if desktop != "a" || 0 <= stallMark || began.IsZero() || world.clock.Now().Before(began.Add(4*time.Second)) {
				return
			}
			stallMark = world.log.mark()
			world.clock.advance("", 90*time.Second)
			other = world.pass("b")
		})
		report := world.pass("a")
		if stallMark < 0 || other == nil {
			t.Errorf("%s: a never stalled", wait.name)
			continue
		}
		if 0 < len(report.Issued) || !slices.Equal(other.Issued, []Id{world.certId}) {
			t.Errorf("%s: a issued %v, b issued %v", wait.name, report.Issued, other.Issued)
		}
		if calls := world.log.since(stallMark, "a", ""); 0 < len(calls) {
			t.Errorf("%s: a sent %d requests after it woke, the first %s", wait.name, len(calls), calls[0].name)
		}
		snapshot := world.snapshot()
		if snapshot.state != TlsCertStateCustomIssued || snapshot.issuedBy != "b" || snapshot.issuedClaimSeq != 2 || !slices.Equal(snapshot.lapsed, []uint64{1}) {
			t.Errorf("%s: %+v", wait.name, snapshot)
		}
		if len(snapshot.writes) != 1 || snapshot.writes[0].claimSeq != 1 || world.log.count("b", "challenge") != 0 {
			t.Errorf("%s: the writes %+v, b's captures %d", wait.name, snapshot.writes, world.log.count("b", "challenge"))
		}
		if world.log.count("", "acme new-order") != 1 || world.log.count("b", "acme new-order") != 0 || world.log.count("", "acme finalize") != 1 || world.log.count("b", "acme challenge") != 0 {
			t.Errorf("%s: %d newOrders, %d by b, %d finalizes, b's challenges %d", wait.name, world.log.count("", "acme new-order"), world.log.count("b", "acme new-order"), world.log.count("", "acme finalize"), world.log.count("b", "acme challenge"))
		}
	}
}

// A wait that never ends ends with the attempt: under its claim, renewed throughout, the holder releases once its next
// poll would reach the attempt's OrderDeadline, measured from the attempt's start and not from the CA's challenge,
// which came 30 s in. The order stays recorded, alive and undeactivated, for the next claim, and nothing is finalized
// twice.
func TestTlsCustomOrdererReleasesAtTheAttemptsEndInEachWait(t *testing.T) {
	settings := DefaultTlsCustomSettings()
	settings.OrderDeadline = 2 * time.Minute
	for _, wait := range tlsCustomLeaseWaits() {
		world := newTlsCustomLeaseWorld(t, 30_000, settings, func(ca *tlsCustomLeaseCa) {
			wait.set(ca, -1)
		})
		world.server.readyAfter = 30 * time.Second
		report := world.pass("a")
		if 0 < len(report.Issued) || 0 < len(report.Failed) {
			t.Errorf("%s: %+v", wait.name, report)
			continue
		}
		releases := world.log.since(0, "a", "progress "+TlsCustomEventRelease)
		claims := world.log.since(0, "a", "claim")
		if len(releases) != 1 || len(claims) == 0 {
			t.Errorf("%s: %d releases, %d claims", wait.name, len(releases), len(claims))
			continue
		}
		if attempt := releases[0].at.Sub(claims[0].at); settings.OrderDeadline < attempt {
			t.Errorf("%s: released %v into an attempt of %v", wait.name, attempt, settings.OrderDeadline)
		}
		snapshot := world.snapshot()
		if snapshot.holder != "" || snapshot.state != TlsCertStateCustomOrdering || snapshot.orderUrl != tlsCustomLeaseOrderUrl || 0 < len(snapshot.lapsed) {
			t.Errorf("%s: %+v", wait.name, snapshot)
		}
		if longest := world.longestUnrenewed("a"); 10*time.Second < longest {
			t.Errorf("%s: a held the lock %v unrenewed", wait.name, longest)
		}
		if world.log.count("a", "progress "+TlsCustomEventOrderInvalid) != 0 || world.log.count("a", "acme deactivate") != 0 || 1 < world.log.count("a", "acme finalize") {
			t.Errorf("%s: %d order_invalid, %d deactivations, %d finalizes", wait.name, world.log.count("a", "progress "+TlsCustomEventOrderInvalid), world.log.count("a", "acme deactivate"), world.log.count("a", "acme finalize"))
		}
	}
}

// A renewal left unanswered keeps the hold until its local deadline: tried again a poll on, it is answered under the
// same claim, and the order goes on to register under it with no lapse.
func TestTlsCustomOrdererRidesOutAnUnansweredRenewal(t *testing.T) {
	world := newTlsCustomLeaseWorld(t, 30_000, nil, func(ca *tlsCustomLeaseCa) {
		ca.issueAfter = time.Minute
	})
	// the routes do not answer a's claims from 9 s to 15 s into the processing poll, across its first renewal
	world.server.unanswered = func(desktop string, route string) bool {
		_, finalizeTime := world.ca.times()
		now := world.clock.Now()
		return desktop == "a" && route == "claim" && !finalizeTime.IsZero() && !now.Before(finalizeTime.Add(9*time.Second)) && now.Before(finalizeTime.Add(15*time.Second))
	}
	report := world.pass("a")
	if !slices.Equal(report.Issued, []Id{world.certId}) {
		t.Fatalf("a issued %v", report.Issued)
	}
	unanswered := 0
	for _, claim := range world.log.since(0, "a", "claim") {
		if claim.refusal == "unanswered" {
			unanswered += 1
		} else if claim.claimSeq != 1 {
			t.Fatalf("a's claim answered %d", claim.claimSeq)
		}
	}
	// at 10 s, 12 s and 14 s, then answered at 16 s
	if unanswered != 3 {
		t.Fatalf("%d unanswered renewals", unanswered)
	}
	if snapshot := world.snapshot(); snapshot.state != TlsCertStateCustomIssued || snapshot.issuedBy != "a" || snapshot.issuedClaimSeq != 1 || 0 < len(snapshot.lapsed) {
		t.Fatalf("%+v", snapshot)
	}
}

// A renewal refused ends the holder's work on the row: the row's device removed under its recorded order moves the row
// to custom_revoking and frees the lock, the holder's next renewal in the processing poll is refused, and after it the
// holder sends nothing more, to the routes or the CA: no register and no release. Before it, only reads of the order.
func TestTlsCustomOrdererStopsAtARefusedRenewal(t *testing.T) {
	world := newTlsCustomLeaseWorld(t, 30_000, nil, func(ca *tlsCustomLeaseCa) {
		ca.issueAfter = time.Minute
	})
	removeMark := -1
	world.clock.setOnWait(func(desktop string) {
		_, finalizeTime := world.ca.times()
		if desktop != "a" || 0 <= removeMark || finalizeTime.IsZero() || world.clock.Now().Before(finalizeTime.Add(4*time.Second)) {
			return
		}
		removeMark = world.log.mark()
		world.server.remove()
	})
	report := world.pass("a")
	if removeMark < 0 || 0 < len(report.Issued) {
		t.Fatalf("removed at %d, a issued %v", removeMark, report.Issued)
	}
	calls := world.log.since(removeMark, "a", "")
	refused := slices.IndexFunc(calls, func(call *tlsCustomLeaseCall) bool {
		return call.name == "claim" && call.refusal == TlsCustomRefusalState
	})
	if refused < 0 || refused != len(calls)-1 {
		t.Fatalf("a's requests after the removal: %d, the refused renewal at %d", len(calls), refused)
	}
	for _, call := range calls[:refused] {
		if call.name != "acme order" {
			t.Fatalf("a sent %s before its renewal was refused", call.name)
		}
	}
	if snapshot := world.snapshot(); snapshot.holder != "" || snapshot.state != TlsCertStateCustomRevoking || snapshot.orderUrl != tlsCustomLeaseOrderUrl {
		t.Fatalf("%+v", snapshot)
	}
}

// 17.2.7's steps 6 and 8 under the claim: a download with no answer is fetched again a poll on, and a register with no
// answer is sent again while the claim renews, each for longer than a third of the lease; the chain registers under
// the first claim, with no release and no lapse.
func TestTlsCustomOrdererFetchesAndRegistersAgainUnderItsClaim(t *testing.T) {
	world := newTlsCustomLeaseWorld(t, 30_000, nil, func(ca *tlsCustomLeaseCa) {
		ca.certificateOutages = 12
	})
	registers := 0
	world.server.unanswered = func(desktop string, route string) bool {
		if route != "register" {
			return false
		}
		registers += 1
		return registers <= 12
	}
	report := world.pass("a")
	if !slices.Equal(report.Issued, []Id{world.certId}) {
		t.Fatalf("a issued %v", report.Issued)
	}
	if fetched := world.log.count("a", "acme certificate"); fetched != 13 {
		t.Fatalf("%d downloads", fetched)
	}
	for _, register := range world.log.since(0, "a", "register") {
		if register.claimSeq != 1 {
			t.Fatalf("a register under claim %d", register.claimSeq)
		}
	}
	if sent := world.log.count("a", "register"); sent != 13 {
		t.Fatalf("%d registers", sent)
	}
	if snapshot := world.snapshot(); snapshot.state != TlsCertStateCustomIssued || snapshot.issuedBy != "a" || snapshot.issuedClaimSeq != 1 || 0 < len(snapshot.lapsed) {
		t.Fatalf("%+v", snapshot)
	}
	if longest := world.longestUnrenewed("a"); 10*time.Second < longest {
		t.Fatalf("a held the lock %v unrenewed", longest)
	}
	if released := world.log.count("a", "progress "+TlsCustomEventRelease); released != 0 {
		t.Fatalf("a released %d times", released)
	}
}
