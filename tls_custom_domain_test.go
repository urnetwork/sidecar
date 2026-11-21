//go:build !sidecar_http && !ios_extension

// The ordering desktop's own parts (TLS-M6-05; DESIGN-DETAILS 17.2.3, 17.2.5, 17.2.7): RFC 7638's thumbprint, the key
// file's format and the check that picks its key against the account row, a dead order by its status, the chain check
// of step 6, the loop's cadence on a clock the test steps, an account's status as `ur tls account status` reads it,
// and the custom routes' client against a scripted api. The orderer's passes run against the real store in server's
// schedule tests. Names are under .example, keys generated.

package sidecar

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestTlsCustomKeyThumbprintIsRfc7638s(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := func(value *big.Int) string {
		bytes := make([]byte, 32)
		value.FillBytes(bytes)
		return base64.RawURLEncoding.EncodeToString(bytes)
	}
	// the required members, lexicographic, no whitespace (RFC 7638 §3.2, §3.3's EC example's shape)
	want := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + coordinate(key.X) + `","y":"` + coordinate(key.Y) + `"}`))
	if got := TlsCustomKeyThumbprint(&key.PublicKey); string(got) != string(want[:]) {
		t.Fatalf("%x, want %x", got, want)
	}
}

func TestTlsCustomKeyFilePicksTheRowsKey(t *testing.T) {
	currentDer, err := NewTlsCustomAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	nextDer, err := NewTlsCustomAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	current, _ := tlsCustomParseKey(currentDer)
	next, _ := tlsCustomParseKey(nextDer)
	file := &TlsCustomKeyFile{Format: 1, Domain: "customer.example", Ca: "letsencrypt", KeySeq: 3, Key: currentDer, ShrunkAt: 7}
	data, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTlsCustomKeyFile(data, "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	account := &TlsCustomAccount{Domain: "customer.example", KeySeq: 3, KeyThumbprint: TlsCustomKeyThumbprint(&current.PublicKey)}
	if key, keySeq := parsed.KeyFor(account); key == nil || keySeq != 3 {
		t.Fatalf("the row's key: %v, %d", key, keySeq)
	}
	// a row at another sequence or thumbprint takes nothing from the file
	for _, other := range []*TlsCustomAccount{
		{Domain: "customer.example", KeySeq: 4, KeyThumbprint: TlsCustomKeyThumbprint(&current.PublicKey)},
		{Domain: "customer.example", KeySeq: 3, KeyThumbprint: TlsCustomKeyThumbprint(&next.PublicKey)},
	} {
		if key, _ := parsed.KeyFor(other); key != nil {
			t.Errorf("a key for %+v", other)
		}
	}
	// the file at s + 1 and the row at s with that key as next: R7 is owed and the file passes
	advanced := &TlsCustomKeyFile{Format: 1, Domain: "customer.example", KeySeq: 4, Key: nextDer}
	owed := &TlsCustomAccount{Domain: "customer.example", KeySeq: 3, KeyThumbprint: TlsCustomKeyThumbprint(&current.PublicKey), NextKeyThumbprint: TlsCustomKeyThumbprint(&next.PublicKey)}
	if key, keySeq := advanced.KeyFor(owed); key == nil || keySeq != 4 {
		t.Fatalf("an owed R7: %v, %d", key, keySeq)
	}
	// refused: another domain, another format, a next that is not the one after
	for _, bad := range []*TlsCustomKeyFile{
		{Format: 1, Domain: "other.example", KeySeq: 3, Key: currentDer},
		{Format: 2, Domain: "customer.example", KeySeq: 3, Key: currentDer},
		{Format: 1, Domain: "customer.example", KeySeq: 3, Key: currentDer, Next: &TlsCustomKeyFileNext{KeySeq: 5, Key: nextDer}},
		{Format: 1, Domain: "customer.example", KeySeq: 3, Key: []byte{1, 2, 3}},
	} {
		data, _ := bad.Marshal()
		if _, err := ParseTlsCustomKeyFile(data, "customer.example"); err == nil {
			t.Errorf("a key file passed: %+v", bad)
		}
	}
	if TlsCustomKeyFilePath("customer.example") != "tls/acme/customer.example.json" {
		t.Errorf("path %s", TlsCustomKeyFilePath("customer.example"))
	}
}

func TestTlsAcmeOrderDeadByStatus(t *testing.T) {
	for status, dead := range map[string]bool{
		TlsAcmeStatusPending:     false,
		TlsAcmeStatusReady:       false,
		TlsAcmeStatusProcessing:  false,
		TlsAcmeStatusValid:       false,
		TlsAcmeStatusInvalid:     true,
		TlsAcmeStatusDeactivated: true,
		"expired":                true,
	} {
		if got := tlsAcmeOrderDead(&TlsAcmeOrder{Status: status}); got != dead {
			t.Errorf("%s: %v", status, got)
		}
	}
	if !tlsAcmeOrderDead(nil) {
		t.Error("no order read as live")
	}
}

func TestTlsCustomOrdererChecksTheChainItRegisters(t *testing.T) {
	now := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 365), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDer, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDer)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"www.customer.example"}}, deviceKey)
	leaf := func(publicKey any, names []string, notAfter time.Time) [][]byte {
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: now, NotAfter: notAfter, DNSNames: names}, caCert, publicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{der, caDer}
	}
	orderer := &TlsCustomDomainOrderer{clock: &tlsCustomTestClock{now: now}, settings: DefaultTlsCustomSettings()}
	row := &TlsCertRecord{CustomHost: "www.customer.example", Csr: csr}
	if _, ok := orderer.checkChain(row, leaf(&deviceKey.PublicKey, []string{"www.customer.example"}, now.Add(time.Hour))); !ok {
		t.Fatal("the row's own chain refused")
	}
	for name, chain := range map[string][][]byte{
		"another key":   leaf(&otherKey.PublicKey, []string{"www.customer.example"}, now.Add(time.Hour)),
		"a second name": leaf(&deviceKey.PublicKey, []string{"www.customer.example", "api.customer.example"}, now.Add(time.Hour)),
		"expired":       leaf(&deviceKey.PublicKey, []string{"www.customer.example"}, now.Add(-time.Second)),
		"unchained":     {leaf(&deviceKey.PublicKey, []string{"www.customer.example"}, now.Add(time.Hour))[0], leaf(&otherKey.PublicKey, []string{"x.example"}, now.Add(time.Hour))[0]},
		"empty":         {},
	} {
		if _, ok := orderer.checkChain(row, chain); ok {
			t.Errorf("%s passed", name)
		}
	}
}

// A clock that stands still.
type tlsCustomTestClock struct {
	now time.Time
}

func (self *tlsCustomTestClock) Now() time.Time {
	return self.now
}

func (self *tlsCustomTestClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.now
	return fired
}

func (self *tlsCustomTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return false }
}

// A TlsCustomApi whose Work answers from a script, counting its calls; every other route refuses.
type tlsCustomScriptedApi struct {
	stateLock sync.Mutex
	works     []*TlsCertsResult
	errs      []error
	workCount int
}

func (self *tlsCustomScriptedApi) Work(ctx context.Context) (*TlsCertsResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	index := min(self.workCount, len(self.works)-1)
	self.workCount += 1
	return self.works[index], self.errs[index]
}

func (self *tlsCustomScriptedApi) Claim(ctx context.Context, args *TlsCustomClaimArgs) (*TlsCustomClaimResult, error) {
	return nil, errors.New("no claim in this test")
}

func (self *tlsCustomScriptedApi) Progress(ctx context.Context, args *TlsCustomProgressArgs) (*TlsCustomClaimResult, error) {
	return nil, errors.New("no progress in this test")
}

func (self *tlsCustomScriptedApi) Register(ctx context.Context, args *TlsCertRegisterArgs) error {
	return errors.New("no register in this test")
}

func (self *tlsCustomScriptedApi) Account(ctx context.Context, args *TlsCustomAccountArgs) (*TlsCustomAccount, error) {
	return nil, errors.New("no account op in this test")
}

func (self *tlsCustomScriptedApi) Challenge(ctx context.Context, args *TlsCustomChallengeArgs) (*TlsCustomChallengeResult, error) {
	return nil, errors.New("no challenge in this test")
}

func (self *tlsCustomScriptedApi) ChallengeStatus(ctx context.Context, challengeId uint64) (*TlsCustomChallengeResult, error) {
	return nil, errors.New("no challenge in this test")
}

// Key files by repo, and the local copies.
type tlsCustomTestKeys struct {
	stateLock sync.Mutex
	files     map[Id][]byte
	locals    map[string][]byte
}

func (self *tlsCustomTestKeys) ReadKeyFile(ctx context.Context, repoId Id, domain string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	data, ok := self.files[repoId]
	if !ok {
		return nil, ErrTlsCustomKeyUnavailable
	}
	return data, nil
}

func (self *tlsCustomTestKeys) WriteKeyFile(ctx context.Context, repoId Id, domain string, data []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.files[repoId] = data
	return nil
}

func (self *tlsCustomTestKeys) LocalKeyFile(domain string) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.locals[domain]
}

func (self *tlsCustomTestKeys) SetLocalKeyFile(domain string, data []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.locals[domain] = data
	return nil
}

// A view with no devices.
type tlsCustomTestDevices struct{}

func (self *tlsCustomTestDevices) Device(sidecarId Id, ownerLabel string) ([]byte, bool) {
	return nil, false
}
func (self *tlsCustomTestDevices) Holds443(ownerLabel string) bool { return false }
func (self *tlsCustomTestDevices) SidecarId() Id                   { return Id{} }
func (self *tlsCustomTestDevices) NetworkId() Id                   { return Id{} }

// A key change due or not, and whether this desktop may make it.
type tlsCustomTestRepos struct {
	due     bool
	mayRoll bool
}

func (self *tlsCustomTestRepos) RolloverDue(repoId Id, shrunkAt uint64) (bool, bool) {
	return self.due, self.mayRoll
}

func (self *tlsCustomTestRepos) RollTarget(ctx context.Context, repoId Id) (Id, uint64, error) {
	return Id{}, 0, ErrTlsCustomRollTarget
}

// A CA no test here reaches.
type tlsCustomUnreachedCa struct {
	TlsAcmeClient
}

// One wait the orderer asked its clock for, which the test fires.
type tlsCustomStep struct {
	timeout time.Duration
	fire    chan time.Time
}

// A clock whose waits go to the test, one at a time.
type tlsCustomStepClock struct {
	steps chan *tlsCustomStep
}

func (self *tlsCustomStepClock) Now() time.Time {
	return time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
}

func (self *tlsCustomStepClock) After(timeout time.Duration) <-chan time.Time {
	step := &tlsCustomStep{timeout: timeout, fire: make(chan time.Time, 1)}
	self.steps <- step
	return step.fire
}

func (self *tlsCustomStepClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// An orderer on api, keys and repos, its clock clock.
func newTlsCustomTestOrderer(t *testing.T, api TlsCustomApi, keys TlsCustomKeyStore, clock Clock, settings *TlsCustomSettings) *TlsCustomDomainOrderer {
	t.Helper()
	orderer, err := NewTlsCustomDomainOrderer(&TlsCustomDomainOrdererDeps{
		Api:     api,
		Acme:    &tlsCustomUnreachedCa{},
		Devices: &tlsCustomTestDevices{},
		Keys:    keys,
		Roots:   []string{"sidecar.example"},
		Clock:   clock,
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	return orderer
}

// 17.2.7's loop: PollInterval after a pass that listed work, IdlePollInterval after one that did not and after one
// that failed, until its context ends.
func TestTlsCustomOrdererRunWaitsByWhatItsPassFound(t *testing.T) {
	api := &tlsCustomScriptedApi{
		works: []*TlsCertsResult{
			{QueuedCsrs: []*TlsCertRecord{{CertId: NewId(), CustomDomain: "customer.example", WaitMs: 1000}}},
			{},
			nil,
		},
		errs: []error{nil, nil, errors.New("api unreachable")},
	}
	settings := DefaultTlsCustomSettings()
	settings.PollJitter = 0
	clock := &tlsCustomStepClock{steps: make(chan *tlsCustomStep)}
	orderer := newTlsCustomTestOrderer(t, api, &tlsCustomTestKeys{files: map[Id][]byte{}, locals: map[string][]byte{}}, clock, settings)
	ctx, cancel := context.WithCancel(context.Background())
	reports := make(chan error, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		orderer.Run(ctx, func(passReport *TlsCustomPassReport, err error) {
			reports <- err
		})
	}()
	for index, want := range []time.Duration{settings.PollInterval, settings.IdlePollInterval, settings.IdlePollInterval} {
		step := <-clock.steps
		if step.timeout != want {
			t.Fatalf("wait %d: %v, want %v", index, step.timeout, want)
		}
		if err := <-reports; (err != nil) != (index == 2) {
			t.Fatalf("pass %d: %v", index, err)
		}
		if index < 2 {
			step.fire <- time.Time{}
		}
	}
	cancel()
	<-done
}

// The jitter moves a wait by at most PollJitter of PollInterval either way.
func TestTlsCustomOrdererRunJittersItsPoll(t *testing.T) {
	api := &tlsCustomScriptedApi{
		works: []*TlsCertsResult{{QueuedCsrs: []*TlsCertRecord{{CertId: NewId(), CustomDomain: "customer.example", WaitMs: 1000}}}},
		errs:  []error{nil},
	}
	settings := DefaultTlsCustomSettings()
	clock := &tlsCustomStepClock{steps: make(chan *tlsCustomStep)}
	orderer := newTlsCustomTestOrderer(t, api, &tlsCustomTestKeys{files: map[Id][]byte{}, locals: map[string][]byte{}}, clock, settings)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		orderer.Run(ctx, nil)
	}()
	spread := time.Duration(settings.PollJitter * float64(settings.PollInterval))
	for range 50 {
		step := <-clock.steps
		if step.timeout < settings.PollInterval-spread || settings.PollInterval+spread < step.timeout {
			t.Fatalf("a wait of %v", step.timeout)
		}
		step.fire <- time.Time{}
	}
	cancel()
	// the loop's next wait sees the cancel
	select {
	case step := <-clock.steps:
		step.fire <- time.Time{}
	case <-done:
	}
	<-done
}

// What `ur tls account status` reads: each account of the work list, its rows, the key this desktop's file gives for
// it, and whether a key change is due and may be made here.
func TestTlsCustomAccountStatusReadsTheHeldKey(t *testing.T) {
	der, err := NewTlsCustomAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := tlsCustomParseKey(der)
	if err != nil {
		t.Fatal(err)
	}
	repoId := NewId()
	file := &TlsCustomKeyFile{Format: tlsCustomKeyFileFormat, Domain: "customer.example", Ca: "letsencrypt", AccountUri: "https://ca.example/acct/1", KeySeq: 3, Key: der, ShrunkAt: 7}
	data, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	held := &TlsCustomAccount{Domain: "customer.example", Ca: "letsencrypt", AccountUri: file.AccountUri, KeySeq: 3, KeyThumbprint: TlsCustomKeyThumbprint(&key.PublicKey), KeyRepoId: repoId}
	other := &TlsCustomAccount{Domain: "other.example", Ca: "letsencrypt", AccountUri: "https://ca.example/acct/2", KeySeq: 1, KeyThumbprint: []byte{1}, KeyRepoId: NewId()}
	api := &tlsCustomScriptedApi{
		works: []*TlsCertsResult{{
			Accounts: []*TlsCustomAccount{held, other},
			QueuedCsrs: []*TlsCertRecord{
				{CertId: NewId(), CustomDomain: "customer.example"},
				{CertId: NewId(), CustomDomain: "customer.example"},
				{CertId: NewId(), CustomDomain: "other.example"},
			},
		}},
		errs: []error{nil},
	}
	keys := &tlsCustomTestKeys{files: map[Id][]byte{repoId: data}, locals: map[string][]byte{}}
	orderer := newTlsCustomTestOrderer(t, api, keys, newTlsTestClock(), nil)
	statuses, err := orderer.AccountStatus(context.Background(), "", &tlsCustomTestRepos{due: true, mayRoll: false})
	if err != nil || len(statuses) != 2 {
		t.Fatalf("%d statuses, %v", len(statuses), err)
	}
	if status := statuses[0]; status.Account.Domain != "customer.example" || status.KeySeq != 3 || !status.RolloverDue || status.MayRoll || status.WorkCount != 2 {
		t.Fatalf("the held account: %+v", status)
	}
	// a file that does not check against the row is no key held, and no change is judged for it
	if status := statuses[1]; status.KeySeq != 0 || status.RolloverDue || status.WorkCount != 1 {
		t.Fatalf("the other account: %+v", status)
	}
	// the read that passed kept the local copy
	if !bytes.Equal(keys.LocalKeyFile("customer.example"), data) {
		t.Fatalf("no local copy")
	}
	statuses, err = orderer.AccountStatus(context.Background(), "other.example", nil)
	if err != nil || len(statuses) != 1 || statuses[0].Account.Domain != "other.example" {
		t.Fatalf("one domain: %+v, %v", statuses, err)
	}
	if account, err := orderer.Account(context.Background(), "absent.example"); err != nil || account != nil {
		t.Fatalf("an absent domain: %+v, %v", account, err)
	}
}

// The custom routes as api answers them (DESIGN-DETAILS 17.2.5): each under the certs service token as a bearer, at its
// path; a refusal whose body is a custom route's is a *TlsCustomError with its row and key sequence, and any other
// stays a *SidecarApiError; an answer missing what makes it the route's is refused.
func TestTlsCustomApiSpeaksTheRoutes(t *testing.T) {
	inFlight := NewId()
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			if request.Header.Get("Authorization") != "Bearer certs-token" {
				return syntheticResponse(request, 401, `{"error":"no token","code":"bad_token"}`, nil), nil
			}
			switch request.Method + " " + request.URL.RequestURI() {
			case "GET /tls/certs?work=1":
				return syntheticResponse(request, 200, `{"certs":[],"accounts":[{"domain":"customer.example","ca":"letsencrypt","account_uri":"https://ca.example/acct/1","key_seq":2,"key_thumbprint":"AQI=","key_repo_id":"`+inFlight.String()+`","acme_name":"abc.acme.sidecar.example"}]}`, nil), nil
			case "POST /tls/custom-claim":
				return syntheticResponse(request, 409, `{"reason":"in_flight","cert_id":"`+inFlight.String()+`"}`, nil), nil
			case "POST /tls/custom-progress":
				return syntheticResponse(request, 409, `{"reason":"key_seq","key_seq":4}`, nil), nil
			case "POST /tls/custom-account":
				return syntheticResponse(request, 429, `{"reason":"hold","retry_after_ms":60000}`, nil), nil
			case "POST /tls/cert-register":
				return syntheticResponse(request, 200, `{}`, nil), nil
			case "POST /tls/custom-challenge":
				return syntheticResponse(request, 200, `{"challenge_id":0}`, nil), nil
			case "GET /tls/custom-challenge/12":
				return syntheticResponse(request, 403, `{"error":"no grant","code":"forbidden"}`, nil), nil
			}
			return syntheticResponse(request, 404, `{}`, nil), nil
		},
	}
	api := NewTlsCustomApi(newTestSidecarApi(t, transport), func(ctx context.Context) (string, error) { return "certs-token", nil })
	ctx := context.Background()
	work, err := api.Work(ctx)
	if err != nil || len(work.Accounts) != 1 || work.Accounts[0].KeySeq != 2 || work.Accounts[0].AcmeName != "abc.acme.sidecar.example" {
		t.Fatalf("the work list: %+v, %v", work, err)
	}
	_, err = api.Claim(ctx, &TlsCustomClaimArgs{Domain: "customer.example", Purpose: TlsCustomPurposeOrder, CertId: NewId(), KeySeq: 2})
	var refusal *TlsCustomError
	if !errors.As(err, &refusal) || refusal.Status != 409 || refusal.Refusal.Reason != TlsCustomRefusalInFlight || refusal.Refusal.CertId != inFlight {
		t.Fatalf("an in_flight claim: %v", err)
	}
	_, err = api.Progress(ctx, &TlsCustomProgressArgs{Domain: "customer.example", ClaimSeq: 3, CertId: NewId(), Event: TlsCustomEventRelease})
	if !errors.As(err, &refusal) || refusal.Refusal.Reason != TlsCustomRefusalKeySeq || refusal.Refusal.KeySeq != 4 {
		t.Fatalf("a key_seq refusal: %v", err)
	}
	_, err = api.Account(ctx, &TlsCustomAccountArgs{Domain: "customer.example", Op: TlsCustomAccountRollBegin})
	if !errors.As(err, &refusal) || refusal.Status != 429 || refusal.Refusal.Reason != TlsCustomRefusalHold || refusal.Refusal.RetryAfterMs != 60000 {
		t.Fatalf("a hold: %v", err)
	}
	if err := api.Register(ctx, &TlsCertRegisterArgs{CertId: NewId(), ClaimSeq: 3, Chain: [][]byte{{1}}, AccountUri: "https://ca.example/acct/1"}); err != nil {
		t.Fatalf("a register: %v", err)
	}
	if _, err := api.Challenge(ctx, &TlsCustomChallengeArgs{Domain: "customer.example", Value: "v"}); !errors.Is(err, ErrSidecarApiReply) {
		t.Fatalf("a challenge with no id: %v", err)
	}
	_, err = api.ChallengeStatus(ctx, 12)
	var apiErr *SidecarApiError
	if errors.As(err, &refusal) || !errors.As(err, &apiErr) || apiErr.Status != 403 || apiErr.Code != "forbidden" {
		t.Fatalf("a refusal that is not a custom route's: %v", err)
	}
	// a body that is no args never reaches api
	if _, err := api.Claim(ctx, &TlsCustomClaimArgs{}); !errors.Is(err, ErrSidecarApiArgs) {
		t.Fatalf("an empty claim: %v", err)
	}
	unauthorized := NewTlsCustomApi(newTestSidecarApi(t, transport), func(ctx context.Context) (string, error) { return "", ErrTlsCertsUnconfigured })
	if _, err := unauthorized.Work(ctx); !errors.Is(err, ErrTlsCertsUnconfigured) {
		t.Fatalf("with no token: %v", err)
	}
}

// A TlsCustomApi for the loop's key change: Work from the script, each claim and progress event recorded, a claim
// refused locked.
type tlsCustomRolloverApi struct {
	tlsCustomScriptedApi
	claims []*TlsCustomClaimArgs
	events []*TlsCustomProgressArgs
}

func (self *tlsCustomRolloverApi) Claim(ctx context.Context, args *TlsCustomClaimArgs) (*TlsCustomClaimResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.claims = append(self.claims, args)
	return nil, &TlsCustomError{Status: 409, Refusal: TlsCustomRefusal{Reason: TlsCustomRefusalLocked, RetryAfterMs: 1000}}
}

func (self *tlsCustomRolloverApi) Progress(ctx context.Context, args *TlsCustomProgressArgs) (*TlsCustomClaimResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, args)
	return &TlsCustomClaimResult{}, nil
}

// A work list with one account whose key file this desktop holds, and that file's key store.
func newTlsCustomRolloverWorld(t *testing.T) (*tlsCustomRolloverApi, *tlsCustomTestKeys) {
	t.Helper()
	der, err := NewTlsCustomAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := tlsCustomParseKey(der)
	if err != nil {
		t.Fatal(err)
	}
	repoId := NewId()
	file := &TlsCustomKeyFile{Format: tlsCustomKeyFileFormat, Domain: "customer.example", Ca: "letsencrypt", AccountUri: "https://ca.example/acct/1", KeySeq: 2, Key: der, ShrunkAt: 5}
	data, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	account := &TlsCustomAccount{Domain: "customer.example", Ca: "letsencrypt", AccountUri: file.AccountUri, KeySeq: 2, KeyThumbprint: TlsCustomKeyThumbprint(&key.PublicKey), KeyRepoId: repoId}
	api := &tlsCustomRolloverApi{tlsCustomScriptedApi: tlsCustomScriptedApi{works: []*TlsCertsResult{{Accounts: []*TlsCustomAccount{account}}}, errs: []error{nil}}}
	return api, &tlsCustomTestKeys{files: map[Id][]byte{repoId: data}, locals: map[string][]byte{}}
}

// A due key change this desktop may not make is reported once as rollover_due, with no claim, and not again while the
// row names the same key (owner decision 425, 17.2.13).
func TestTlsCustomOrdererReportsADueChangeItMayNotMake(t *testing.T) {
	api, keys := newTlsCustomRolloverWorld(t)
	orderer, err := NewTlsCustomDomainOrderer(&TlsCustomDomainOrdererDeps{
		Api: api, Acme: &tlsCustomUnreachedCa{}, Devices: &tlsCustomTestDevices{}, Keys: keys, Roots: []string{"sidecar.example"},
		Clock: newTlsTestClock(), Repos: &tlsCustomTestRepos{due: true, mayRoll: false},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for pass := range 3 {
		report, err := orderer.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if reported := 0 < len(report.RolloverDue); reported != (pass == 0) {
			t.Fatalf("pass %d reported %v", pass, report.RolloverDue)
		}
	}
	if len(api.events) != 1 || api.events[0].Event != TlsCustomEventRolloverDue || api.events[0].ClaimSeq != 0 || api.events[0].Domain != "customer.example" {
		t.Fatalf("the events: %+v", api.events)
	}
	if len(api.claims) != 0 {
		t.Fatalf("a claim for a change this desktop may not make: %+v", api.claims)
	}
}

// A due key change this desktop may make is begun in the pass with a rollover claim, and a claim refused leaves it
// due for the next pass, reporting nothing (owner decision 425: within one poll).
func TestTlsCustomOrdererMakesADueChangeItMay(t *testing.T) {
	api, keys := newTlsCustomRolloverWorld(t)
	orderer, err := NewTlsCustomDomainOrderer(&TlsCustomDomainOrdererDeps{
		Api: api, Acme: &tlsCustomUnreachedCa{}, Devices: &tlsCustomTestDevices{}, Keys: keys, Roots: []string{"sidecar.example"},
		Clock: newTlsTestClock(), Repos: &tlsCustomTestRepos{due: true, mayRoll: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		report, err := orderer.RunOnce(context.Background())
		if err != nil || 0 < len(report.Rolled) || 0 < len(report.RolloverDue) {
			t.Fatalf("a pass whose claim was refused: %+v, %v", report, err)
		}
	}
	if len(api.claims) != 2 || api.claims[0].Purpose != TlsCustomPurposeRollover || api.claims[0].KeySeq != 2 || api.claims[0].CertId != (Id{}) {
		t.Fatalf("the claims: %+v", api.claims)
	}
	if len(api.events) != 0 {
		t.Fatalf("events from a desktop that may make the change: %+v", api.events)
	}
}

// What a test's POST loses after api captured it: the write is made, and the desktop hears nothing.
var errTlsCustomTestAnswerLost = errors.New("the connection closed before the answer")

// One receipt of the receipt api: the digest it holds, the serial its write took, and whether GET answered that serial
// stale.
type tlsCustomTestReceipt struct {
	value  string
	serial uint64
	stale  bool
}

// One DNS write the receipt api made: under which claim, of which digest, at which serial.
type tlsCustomTestWrite struct {
	claimSeq uint64
	value    string
	serial   uint64
}

// The custom routes as api and the certs worker answer one desktop's DNS-01 for one row (17.2.6, 17.2.9; owner
// decision 680). The account's lock is taken at the next claim sequence by a claim while free, renewed at the same
// sequence by the holder's claim, and freed by release. There is one receipt a claim: a capture writes its digest at
// the next serial, a capture of the same digest under the claim answers that serial again with no write, and once
// GET has answered the serial stale the next capture of the digest writes it again at a new serial. posts scripts each
// POST by its index: nil captures and answers, errTlsCustomTestAnswerLost captures and loses the answer, and any other
// error is the answer, with no capture.
type tlsCustomReceiptApi struct {
	tlsCustomScriptedApi
	record  *TlsCertRecord
	leaseMs uint32
	posts   func(index int) error
	// by serial, the answers GET gives in turn, the last repeating; ready for a serial with none
	readiness map[uint64][]string

	claimSeq uint64
	held     bool
	receipts map[uint64]*tlsCustomTestReceipt
	serial   uint64
	claims   []*TlsCustomClaimArgs
	events   []*TlsCustomProgressArgs
	// the claim each POST came under, 0 while the lock was free
	postClaimSeqs []uint64
	writes        []tlsCustomTestWrite
	statusReads   []uint64
}

func (self *tlsCustomReceiptApi) Claim(ctx context.Context, args *TlsCustomClaimArgs) (*TlsCustomClaimResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.claims = append(self.claims, args)
	if !self.held {
		self.claimSeq += 1
		self.held = true
	}
	return &TlsCustomClaimResult{ClaimSeq: self.claimSeq, LeaseMs: self.leaseMs, Record: self.record}, nil
}

func (self *tlsCustomReceiptApi) Progress(ctx context.Context, args *TlsCustomProgressArgs) (*TlsCustomClaimResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, args)
	if args.Event == TlsCustomEventRelease {
		self.held = false
	}
	return &TlsCustomClaimResult{}, nil
}

func (self *tlsCustomReceiptApi) Challenge(ctx context.Context, args *TlsCustomChallengeArgs) (*TlsCustomChallengeResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	index := len(self.postClaimSeqs)
	claimSeq := uint64(0)
	if self.held {
		claimSeq = self.claimSeq
	}
	self.postClaimSeqs = append(self.postClaimSeqs, claimSeq)
	var answerErr error
	if self.posts != nil {
		answerErr = self.posts(index)
	}
	if answerErr != nil && answerErr != errTlsCustomTestAnswerLost {
		return nil, answerErr
	}
	if !self.held {
		return nil, &TlsCustomError{Status: http.StatusConflict, Refusal: TlsCustomRefusal{Reason: TlsCustomRefusalClaim}}
	}
	receipt := self.receipts[claimSeq]
	if receipt == nil || receipt.value != args.Value || receipt.stale {
		// the claim's first capture, another digest, or the digest a stale verdict owes again: a write
		self.serial += 1
		receipt = &tlsCustomTestReceipt{value: args.Value, serial: self.serial}
		self.receipts[claimSeq] = receipt
		self.writes = append(self.writes, tlsCustomTestWrite{claimSeq: claimSeq, value: args.Value, serial: self.serial})
	}
	if answerErr != nil {
		return nil, answerErr
	}
	return &TlsCustomChallengeResult{ChallengeId: receipt.serial}, nil
}

func (self *tlsCustomReceiptApi) ChallengeStatus(ctx context.Context, challengeId uint64) (*TlsCustomChallengeResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	readCount := 0
	for _, read := range self.statusReads {
		if read == challengeId {
			readCount += 1
		}
	}
	self.statusReads = append(self.statusReads, challengeId)
	readiness := TlsCustomReadinessReady
	if answers := self.readiness[challengeId]; 0 < len(answers) {
		readiness = answers[min(readCount, len(answers)-1)]
	}
	if readiness == TlsCustomReadinessStale {
		// the verdict is recorded on the receipt whose write took the serial
		for _, receipt := range self.receipts {
			if receipt.serial == challengeId {
				receipt.stale = true
			}
		}
	}
	return &TlsCustomChallengeResult{ChallengeId: challengeId, Readiness: readiness}, nil
}

// The values the acme name's TXT holds: each digest written.
func (self *tlsCustomReceiptApi) txt() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	values := []string{}
	for _, write := range self.writes {
		values = append(values, write.value)
	}
	return values
}

// How many progress events of a kind api heard.
func (self *tlsCustomReceiptApi) eventCount(event string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, args := range self.events {
		if args.Event == event {
			count += 1
		}
	}
	return count
}

// Public DNS as the customer delegated it: _acme-challenge to the account's acme name, whose TXT api writes.
type tlsCustomDnsResolver struct {
	acmeName string
	api      *tlsCustomReceiptApi
}

func (self *tlsCustomDnsResolver) LookupCname(ctx context.Context, name string) (string, error) {
	return self.acmeName + ".", nil
}

func (self *tlsCustomDnsResolver) LookupTxt(ctx context.Context, name string) ([]string, error) {
	return self.api.txt(), nil
}

// A CA whose one order is pending on one authorization offering dns-01, which goes valid, and the order ready, once
// its challenge is answered. Each method runs on the test's goroutine.
type tlsCustomDnsCa struct {
	tlsCustomUnreachedCa
	authorizationUrl string
	challengeUrl     string
	token            string
	challengeCount   int
	deactivateCount  int
}

func (self *tlsCustomDnsCa) Authorization(ctx context.Context, key crypto.Signer, accountUri string, url string) (*TlsAcmeAuthorization, error) {
	status := TlsAcmeStatusPending
	if 0 < self.challengeCount {
		status = TlsAcmeStatusValid
	}
	return &TlsAcmeAuthorization{
		Url:        url,
		Status:     status,
		Challenges: []*TlsAcmeChallenge{{Type: TlsAcmeChallengeDns, Url: self.challengeUrl, Token: self.token, Status: status}},
	}, nil
}

func (self *tlsCustomDnsCa) KeyAuthorization(key crypto.Signer, token string) (string, error) {
	return token + ".thumbprint", nil
}

func (self *tlsCustomDnsCa) Challenge(ctx context.Context, key crypto.Signer, accountUri string, url string) error {
	self.challengeCount += 1
	return nil
}

func (self *tlsCustomDnsCa) Order(ctx context.Context, key crypto.Signer, accountUri string, orderUrl string) (*TlsAcmeOrder, error) {
	status := TlsAcmeStatusPending
	if 0 < self.challengeCount {
		status = TlsAcmeStatusReady
	}
	return &TlsAcmeOrder{Url: orderUrl, Status: status, Authorizations: []string{self.authorizationUrl}}, nil
}

func (self *tlsCustomDnsCa) DeactivateAuthorization(ctx context.Context, key crypto.Signer, accountUri string, url string) error {
	self.deactivateCount += 1
	return nil
}

// A clock each wait of which passes at once, moving its time on by the wait, which it records.
type tlsCustomJumpClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []time.Duration
}

func (self *tlsCustomJumpClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *tlsCustomJumpClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.waits = append(self.waits, timeout)
	self.now = self.now.Add(max(timeout, 0))
	fired := make(chan time.Time, 1)
	fired <- self.now
	return fired
}

func (self *tlsCustomJumpClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// One desktop's DNS-01 for one row, its claim taken under a lease of leaseMs and its order's attempt begun: the
// orderer on the receipt api, the CA and the resolver, on a clock whose waits pass at once.
type tlsCustomDnsWorld struct {
	api     *tlsCustomReceiptApi
	ca      *tlsCustomDnsCa
	clock   *tlsCustomJumpClock
	orderer *TlsCustomDomainOrderer
	hold    *tlsCustomHold
	key     *ecdsa.PrivateKey
	order   *TlsAcmeOrder
}

func newTlsCustomDnsWorld(t *testing.T, settings *TlsCustomSettings, leaseMs uint32, posts func(index int) error) *tlsCustomDnsWorld {
	t.Helper()
	row := &TlsCertRecord{CertId: NewId(), CustomHost: "www.customer.example", CustomDomain: "customer.example", Owner: "shop"}
	api := &tlsCustomReceiptApi{record: row, leaseMs: leaseMs, posts: posts, readiness: map[uint64][]string{}, receipts: map[uint64]*tlsCustomTestReceipt{}}
	account := &TlsCustomAccount{Domain: "customer.example", Ca: "letsencrypt", AccountUri: "https://ca.example/acct/1", KeySeq: 1, AcmeName: "a1b2c3.acme.sidecar.example"}
	ca := &tlsCustomDnsCa{authorizationUrl: "https://ca.example/authz/1", challengeUrl: "https://ca.example/chall/1", token: "token-1"}
	clock := &tlsCustomJumpClock{now: time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)}
	orderer, err := NewTlsCustomDomainOrderer(&TlsCustomDomainOrdererDeps{
		Api:      api,
		Acme:     ca,
		Resolver: &tlsCustomDnsResolver{acmeName: account.AcmeName, api: api},
		Devices:  &tlsCustomTestDevices{},
		Keys:     &tlsCustomTestKeys{files: map[Id][]byte{}, locals: map[string][]byte{}},
		Roots:    []string{"sidecar.example"},
		Clock:    clock,
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := orderer.claim(context.Background(), account, &TlsCustomClaimArgs{Domain: account.Domain, Purpose: TlsCustomPurposeOrder, CertId: row.CertId, KeySeq: 1})
	if err != nil {
		t.Fatal(err)
	}
	// as step 4 begins the attempt (17.2.7)
	hold.attemptStart = clock.Now()
	return &tlsCustomDnsWorld{
		api:     api,
		ca:      ca,
		clock:   clock,
		orderer: orderer,
		hold:    hold,
		key:     key,
		order:   &TlsAcmeOrder{Url: "https://ca.example/order/1", Status: TlsAcmeStatusPending, Authorizations: []string{ca.authorizationUrl}},
	}
}

// Step 5's pending order through 17.2.9's DNS-01: the order it answers, or done once the row was handed back.
func (self *tlsCustomDnsWorld) authorize() (*TlsAcmeOrder, bool) {
	return self.orderer.authorize(context.Background(), &TlsCustomPassReport{}, self.hold, self.key, self.order)
}

// Owner decision 680: a POST whose answer is lost after api captured it is sent again under the same claim, whose
// receipt answers it with the first write's serial; nothing is written twice, and the claim is not released.
func TestTlsCustomOrdererRetriesALostChallengeAnswerUnderItsClaim(t *testing.T) {
	world := newTlsCustomDnsWorld(t, DefaultTlsCustomSettings(), 120_000, func(index int) error {
		if index == 0 {
			return errTlsCustomTestAnswerLost
		}
		return nil
	})
	order, done := world.authorize()
	if done || order == nil || order.Status != TlsAcmeStatusReady {
		t.Fatalf("the authorization after a lost answer: %+v, done %v", order, done)
	}
	if !slices.Equal(world.api.postClaimSeqs, []uint64{1, 1}) {
		t.Fatalf("the POSTs came under claims %v", world.api.postClaimSeqs)
	}
	if len(world.api.writes) != 1 || world.api.writes[0].serial != 1 {
		t.Fatalf("the writes: %+v", world.api.writes)
	}
	if !slices.Equal(world.api.statusReads, []uint64{1}) {
		t.Fatalf("GET asked about serials %v", world.api.statusReads)
	}
	if world.api.claimSeq != 1 || world.api.eventCount(TlsCustomEventRelease) != 0 || world.hold.lost {
		t.Fatalf("the claim: at %d, %d releases, lost %v", world.api.claimSeq, world.api.eventCount(TlsCustomEventRelease), world.hold.lost)
	}
	if world.clock.waits[0] != DefaultTlsCustomSettings().OrderPollInterval {
		t.Fatalf("the retry waited %v", world.clock.waits[0])
	}
	if world.ca.challengeCount != 1 {
		t.Fatalf("the CA's challenge was answered %d times", world.ca.challengeCount)
	}
}

// A confirmed stale verdict still lets the same digest be written again, under the same claim and at a new serial,
// which GET is asked about next; a lost answer to that POST is recovered with the new serial, not a third write.
func TestTlsCustomOrdererWritesTheSameDigestAgainAfterAStaleVerdict(t *testing.T) {
	world := newTlsCustomDnsWorld(t, DefaultTlsCustomSettings(), 120_000, func(index int) error {
		if index == 1 {
			return errTlsCustomTestAnswerLost
		}
		return nil
	})
	world.api.readiness[1] = []string{TlsCustomReadinessStale}
	order, done := world.authorize()
	if done || order == nil || order.Status != TlsAcmeStatusReady {
		t.Fatalf("the authorization after a stale verdict: %+v, done %v", order, done)
	}
	writes := world.api.writes
	if len(writes) != 2 || writes[0].serial != 1 || writes[1].serial != 2 || writes[0].value != writes[1].value || writes[0].claimSeq != 1 || writes[1].claimSeq != 1 {
		t.Fatalf("the writes: %+v", writes)
	}
	if !slices.Equal(world.api.postClaimSeqs, []uint64{1, 1, 1}) {
		t.Fatalf("the POSTs came under claims %v", world.api.postClaimSeqs)
	}
	if !slices.Equal(world.api.statusReads, []uint64{1, 2}) {
		t.Fatalf("GET asked about serials %v", world.api.statusReads)
	}
	if world.api.eventCount(TlsCustomEventRelease) != 0 || world.hold.lost || world.ca.challengeCount != 1 {
		t.Fatalf("%d releases, lost %v, %d challenges", world.api.eventCount(TlsCustomEventRelease), world.hold.lost, world.ca.challengeCount)
	}
}

// A refusal decides how a failed POST ends the work, after that one POST and with nothing written: 409 claim and 403
// lose the hold, with no release; any other refusal, which no retry under the claim changes, releases the claim. The
// CA's challenge is never answered.
func TestTlsCustomOrdererEndsAChallengeWriteByItsRefusal(t *testing.T) {
	for _, c := range []struct {
		refusal  error
		released bool
	}{
		{refusal: &TlsCustomError{Status: http.StatusConflict, Refusal: TlsCustomRefusal{Reason: TlsCustomRefusalClaim}}, released: false},
		{refusal: &TlsCustomError{Status: http.StatusForbidden, Refusal: TlsCustomRefusal{Reason: TlsCustomRefusalGrant}}, released: false},
		{refusal: &TlsCustomError{Status: http.StatusNotFound, Refusal: TlsCustomRefusal{Reason: TlsCustomRefusalNoAccount}}, released: true},
		{refusal: &SidecarApiError{Route: "POST /tls/custom-challenge", Status: http.StatusBadRequest}, released: true},
	} {
		world := newTlsCustomDnsWorld(t, DefaultTlsCustomSettings(), 120_000, func(index int) error {
			return c.refusal
		})
		if order, done := world.authorize(); !done || order != nil {
			t.Errorf("%v: answered %+v, done %v", c.refusal, order, done)
			continue
		}
		if len(world.api.postClaimSeqs) != 1 || len(world.api.writes) != 0 || world.ca.challengeCount != 0 {
			t.Errorf("%v: %d POSTs, %d writes, %d challenges", c.refusal, len(world.api.postClaimSeqs), len(world.api.writes), world.ca.challengeCount)
		}
		if released := world.api.eventCount(TlsCustomEventRelease) == 1; released != c.released || world.hold.lost == c.released {
			t.Errorf("%v: released %v, lost %v", c.refusal, released, world.hold.lost)
		}
	}
}

// 409 in_flight and 429 budget are asked again under the same claim once their retry_after has passed, the claim
// renewed once its renewal comes due while the holder waits: a retry_after longer than a third of the lease is cut
// there, the claim renewed, and the rest waited out.
func TestTlsCustomOrdererWaitsOutAChallengeRefusalsRetryAfter(t *testing.T) {
	world := newTlsCustomDnsWorld(t, DefaultTlsCustomSettings(), 120_000, func(index int) error {
		switch index {
		case 0:
			return &TlsCustomError{Status: http.StatusConflict, Refusal: TlsCustomRefusal{Reason: TlsCustomRefusalInFlight, CertId: NewId(), RetryAfterMs: 45_000}}
		case 1:
			return &TlsCustomError{Status: http.StatusTooManyRequests, Refusal: TlsCustomRefusal{Reason: TlsCustomRefusalBudget, RetryAfterMs: 5_000}}
		}
		return nil
	})
	order, done := world.authorize()
	if done || order == nil || order.Status != TlsAcmeStatusReady {
		t.Fatalf("the authorization: %+v, done %v", order, done)
	}
	// 45 s cut at the renewal 40 s into the 120 s lease, then 5 s
	if len(world.clock.waits) < 3 || world.clock.waits[0] != 40*time.Second || world.clock.waits[1] != 5*time.Second || world.clock.waits[2] != 5*time.Second {
		t.Fatalf("the waits: %v", world.clock.waits)
	}
	if !slices.Equal(world.api.postClaimSeqs, []uint64{1, 1, 1}) || len(world.api.writes) != 1 {
		t.Fatalf("the POSTs came under claims %v, writing %+v", world.api.postClaimSeqs, world.api.writes)
	}
	// the claim, its renewal a third of the lease on, inside the 45 s wait, and the one before the CA's challenge
	if len(world.api.claims) != 3 || world.api.claimSeq != 1 || world.api.eventCount(TlsCustomEventRelease) != 0 {
		t.Fatalf("%d claims, at %d, %d releases", len(world.api.claims), world.api.claimSeq, world.api.eventCount(TlsCustomEventRelease))
	}
}

// A POST the server keeps failing, its write still owed, is sent again under the same claim, renewed as it comes due,
// until the attempt's OrderDeadline, where the claim is released and the order stays recorded, never killed.
func TestTlsCustomOrdererReleasesAFailingChallengeWriteAtTheAttemptsDeadline(t *testing.T) {
	settings := DefaultTlsCustomSettings()
	settings.OrderDeadline = time.Minute
	world := newTlsCustomDnsWorld(t, settings, 30_000, func(index int) error {
		return &SidecarApiError{Route: "POST /tls/custom-challenge", Status: http.StatusServiceUnavailable}
	})
	start := world.clock.Now()
	if order, done := world.authorize(); !done || order != nil {
		t.Fatalf("answered %+v, done %v", order, done)
	}
	if world.api.eventCount(TlsCustomEventRelease) != 1 || world.api.eventCount(TlsCustomEventOrderInvalid) != 0 || world.ca.deactivateCount != 0 || world.ca.challengeCount != 0 {
		t.Fatalf("%d releases, %d order_invalid, %d deactivations, %d challenges", world.api.eventCount(TlsCustomEventRelease), world.api.eventCount(TlsCustomEventOrderInvalid), world.ca.deactivateCount, world.ca.challengeCount)
	}
	// a POST every OrderPollInterval from the attempt's start, the last one before the deadline
	if postCount := len(world.api.postClaimSeqs); postCount != int(settings.OrderDeadline/settings.OrderPollInterval) {
		t.Fatalf("%d POSTs", postCount)
	}
	for _, claimSeq := range world.api.postClaimSeqs {
		if claimSeq != 1 {
			t.Fatalf("the POSTs came under claims %v", world.api.postClaimSeqs)
		}
	}
	if elapsed := world.clock.Now().Sub(start); settings.OrderDeadline < elapsed {
		t.Fatalf("released %v into an attempt of %v", elapsed, settings.OrderDeadline)
	}
	// a lease of 30 s, renewed every 10 s of the minute's waits
	if len(world.api.claims) != 6 || world.api.claimSeq != 1 {
		t.Fatalf("%d claims, at %d", len(world.api.claims), world.api.claimSeq)
	}
}

// While GET waits for the edges, the claim is renewed as it comes due, so a wait longer than the lease leaves the
// holder its claim, and the CA's challenge goes out under it; a lapsed hold would leave the row to a new claim, whose
// receipt is new and its write a second one.
func TestTlsCustomOrdererKeepsItsClaimWhileTheEdgesCatchUp(t *testing.T) {
	world := newTlsCustomDnsWorld(t, DefaultTlsCustomSettings(), 30_000, nil)
	readiness := []string{}
	for range 20 {
		readiness = append(readiness, "waiting")
	}
	world.api.readiness[1] = append(readiness, TlsCustomReadinessReady)
	order, done := world.authorize()
	if done || order == nil || order.Status != TlsAcmeStatusReady {
		t.Fatalf("the authorization after 40 s of waiting under a 30 s lease: %+v, done %v, lost %v", order, done, world.hold.lost)
	}
	if len(world.api.writes) != 1 || !slices.Equal(world.api.postClaimSeqs, []uint64{1}) || world.ca.challengeCount != 1 {
		t.Fatalf("%d writes, POSTs under %v, %d challenges", len(world.api.writes), world.api.postClaimSeqs, world.ca.challengeCount)
	}
	if len(world.api.claims) < 4 || world.api.claimSeq != 1 || world.api.eventCount(TlsCustomEventRelease) != 0 {
		t.Fatalf("%d claims, at %d, %d releases", len(world.api.claims), world.api.claimSeq, world.api.eventCount(TlsCustomEventRelease))
	}
}
