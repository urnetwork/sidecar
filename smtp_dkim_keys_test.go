//go:build !sidecar_http

package sidecar

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The domains a test signs under: .example names, never a real one.
const (
	testDkimNetworkDomain = "n1.root.example"
	testDkimBurnerDomain  = "quietfox.n1.root.example"
	testDkimTeamDomain    = "mail.team.example"
)

// A clock a test moves by hand. No DKIM path waits on it, so After and AfterFunc never fire.
type smtpDkimTestClock struct {
	stateLock sync.Mutex
	current   time.Time
}

func newSmtpDkimTestClock() *smtpDkimTestClock {
	return &smtpDkimTestClock{current: time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)}
}

func (self *smtpDkimTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

func (self *smtpDkimTestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *smtpDkimTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

func (self *smtpDkimTestClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.current = self.current.Add(by)
}

// POST /smtp/dkim-keys in memory: each call is recorded, then answered by err, or by an echo.
type smtpDkimTestPublisher struct {
	stateLock sync.Mutex
	calls     []*SmtpDkimKeysArgs
	err       error
}

func (self *smtpDkimTestPublisher) SmtpDkimKeys(ctx context.Context, args *SmtpDkimKeysArgs) (*SmtpDkimKeysResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, args)
	if self.err != nil {
		return nil, self.err
	}
	result := &SmtpDkimKeysResult{}
	for _, publish := range args.Publish {
		result.Published = append(result.Published, publish.Selector)
	}
	for _, retire := range args.Retire {
		result.Retired = append(result.Retired, retire.Selector)
	}
	return result, nil
}

func (self *smtpDkimTestPublisher) callCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.calls)
}

func (self *smtpDkimTestPublisher) lastCall() *SmtpDkimKeysArgs {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.calls[len(self.calls)-1]
}

func (self *smtpDkimTestPublisher) setErr(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.err = err
}

// An open instance with testNetworkId's keychain, and the DKIM namespace of it.
func newSmtpDkimTestSecrets(t *testing.T) (*SidecarInstance, SidecarSecrets) {
	t.Helper()
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := instance.createKeychain(testNetworkId); err != nil {
		t.Fatal(err)
	}
	return instance, instance.secrets(testNetworkId, SmtpDkimSecretsNamespace)
}

// Keys on secrets, published through publisher, on clock.
func newSmtpDkimTestKeys(secrets SidecarSecrets, publisher SmtpDkimPublisher, clock Clock) *SmtpDkimKeys {
	return NewSmtpDkimKeys(secrets, publisher, DefaultSmtpSenderSettings(), clock, nil)
}

// Signs a digest under selector and checks it against the public key the selector was published with.
func checkSmtpDkimSigns(t *testing.T, selector *SmtpDkimSelector) {
	t.Helper()
	digest := sha256.Sum256([]byte("synthetic signing input"))
	signature, err := selector.SignDkim(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(selector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(parsed.(*rsa.PublicKey), crypto.SHA256, digest[:], signature); err != nil {
		t.Error(err)
	}
	if len(signature) != SmtpDkimRsaKeyBitCount/8 {
		t.Errorf("a %d-octet signature", len(signature))
	}
}

// §14.6: a domain's first use makes a key, publishes it and waits for the answer, and only then does
// the selector sign. Its form is plan-SMTP-small-readings#5's.
func TestSmtpDkimFirstUsePublishesBeforeSigning(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	selector, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	if publisher.callCount() != 1 {
		t.Fatalf("%d calls", publisher.callCount())
	}
	call := publisher.lastCall()
	if len(call.Publish) != 1 || len(call.Retire) != 0 || call.Publish[0].Selector != selector.Selector || call.Publish[0].Domain != testDkimNetworkDomain {
		t.Fatalf("call %+v", call)
	}
	if !bytes.Equal(call.Publish[0].PublicKey, selector.PublicKey) || !smtpDkimPublicKeyValid(selector.PublicKey) {
		t.Error("published key is not the selector's rsa-2048 key")
	}
	if !smtpDkimSelectorForm(selector.Selector) || len(selector.Selector) != 26 || strings.ToLower(selector.Selector) != selector.Selector {
		t.Errorf("selector %q", selector.Selector)
	}
	checkSmtpDkimSigns(t, selector)

	// the same domain, any case, signs under the same selector with no second call
	again, err := keys.Current(context.Background(), strings.ToUpper(testDkimNetworkDomain))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Release()
	if again.Selector != selector.Selector || publisher.callCount() != 1 {
		t.Errorf("selector %s after %d calls", again.Selector, publisher.callCount())
	}
}

func TestSmtpDkimSecondDomainGetsSecondKey(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	first, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	second, err := keys.Current(context.Background(), testDkimTeamDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	if first.Selector == second.Selector || bytes.Equal(first.PublicKey, second.PublicKey) || second.Domain != testDkimTeamDomain {
		t.Error("the second domain shares the first's key")
	}
	if publisher.callCount() != 2 || len(publisher.lastCall().Retire) != 0 {
		t.Error("a second domain retired the first")
	}
	checkSmtpDkimSigns(t, second)
}

// §14.6: at 90 days one call publishes the successor and retires the old selector, and not before.
func TestSmtpDkimRotationPublishesAndRetiresInOneCall(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	clock := newSmtpDkimTestClock()
	keys := newSmtpDkimTestKeys(secrets, publisher, clock)
	first, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	first.Release()

	clock.advance(90*24*time.Hour - time.Second)
	early, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	early.Release()
	if early.Selector != first.Selector || publisher.callCount() != 1 {
		t.Fatal("rotated before 90 days")
	}

	clock.advance(time.Second)
	rotated, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Release()
	if publisher.callCount() != 2 {
		t.Fatalf("%d calls", publisher.callCount())
	}
	call := publisher.lastCall()
	if len(call.Publish) != 1 || call.Publish[0].Selector != rotated.Selector || len(call.Retire) != 1 || call.Retire[0].Selector != first.Selector {
		t.Fatalf("rotation call %+v", call)
	}
	if rotated.Selector == first.Selector {
		t.Error("no new selector")
	}
	checkSmtpDkimSigns(t, rotated)
}

// A send pins its selector at the preamble, so a rotation before it signs leaves it signing under the
// selector it declared, past the 7 days a retired key is kept, until it releases it.
func TestSmtpDkimSendInFlightKeepsItsSelector(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	clock := newSmtpDkimTestClock()
	keys := newSmtpDkimTestKeys(secrets, publisher, clock)
	inFlight, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}

	clock.advance(90 * 24 * time.Hour)
	if err := keys.Rotate(context.Background(), testDkimNetworkDomain); err != nil {
		t.Fatal(err)
	}
	clock.advance(8 * 24 * time.Hour)
	next, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Release()
	if next.Selector == inFlight.Selector {
		t.Fatal("no rotation")
	}
	checkSmtpDkimSigns(t, inFlight)

	// released, the next call purges it
	inFlight.Release()
	inFlight.Release()
	later, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer later.Release()
	digest := sha256.Sum256(nil)
	if _, err := inFlight.SignDkim(digest[:]); !errors.Is(err, ErrSmtpDkimSelectorGone) {
		t.Errorf("a purged selector signed: %v", err)
	}
	names, err := secrets.List("")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(names, smtpDkimKeyRecordName(inFlight.Selector)) || slices.Contains(names, smtpDkimSelectorRecordName(inFlight.Selector)) {
		t.Errorf("records left: %v", names)
	}
}

// A retired key stays 7 days, as long as DNS keeps its selector, then goes.
func TestSmtpDkimRetiredKeyKeptSevenDays(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	clock := newSmtpDkimTestClock()
	keys := newSmtpDkimTestKeys(secrets, publisher, clock)
	old, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	old.Release()
	if err := keys.Rotate(context.Background(), testDkimNetworkDomain); err != nil {
		t.Fatal(err)
	}
	clock.advance(7*24*time.Hour - time.Second)
	if _, err := keys.Current(context.Background(), testDkimNetworkDomain); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(nil)
	if _, err := old.SignDkim(digest[:]); err != nil {
		t.Errorf("gone before 7 days: %v", err)
	}
	clock.advance(time.Second)
	if _, err := keys.Current(context.Background(), testDkimNetworkDomain); err != nil {
		t.Fatal(err)
	}
	if _, err := old.SignDkim(digest[:]); !errors.Is(err, ErrSmtpDkimSelectorGone) {
		t.Errorf("kept past 7 days: %v", err)
	}
}

// §15.9: a burn retires the burner's last selector, in one call, and no send pins it after.
func TestSmtpDkimBurnRetiresTheBurnersSelector(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	network, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Release()
	burner, err := keys.Current(context.Background(), testDkimBurnerDomain)
	if err != nil {
		t.Fatal(err)
	}
	burner.Release()
	if err := keys.Retire(context.Background(), testDkimBurnerDomain); err != nil {
		t.Fatal(err)
	}
	call := publisher.lastCall()
	if len(call.Publish) != 0 || len(call.Retire) != 1 || call.Retire[0].Selector != burner.Selector || call.Retire[0].Domain != testDkimBurnerDomain {
		t.Fatalf("burn call %+v", call)
	}
	records, err := keys.loadWithPublishLock()
	if err != nil {
		t.Fatal(err)
	}
	if records[burner.Selector].State != smtpDkimStateRetired || records[network.Selector].State != smtpDkimStatePublished {
		t.Error("the burn retired the wrong selector")
	}
	// retiring again, or a domain with no selector, sends nothing
	calls := publisher.callCount()
	if err := keys.Retire(context.Background(), testDkimBurnerDomain); err != nil {
		t.Fatal(err)
	}
	if err := keys.Retire(context.Background(), "other.n1.root.example"); err != nil {
		t.Fatal(err)
	}
	if publisher.callCount() != calls {
		t.Error("a retire with nothing to retire was sent")
	}
}

// A retire whose answer was lost never signs again, and the next call sends it again.
func TestSmtpDkimUnansweredRetireIsSentAgain(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	burner, err := keys.Current(context.Background(), testDkimBurnerDomain)
	if err != nil {
		t.Fatal(err)
	}
	burner.Release()
	publisher.setErr(errors.New("synthetic transport failure"))
	if err := keys.Retire(context.Background(), testDkimBurnerDomain); err == nil {
		t.Fatal("a failed retire succeeded")
	}
	publisher.setErr(nil)
	calls := publisher.callCount()
	network, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Release()
	retried := false
	for _, call := range publisher.calls[calls:] {
		if len(call.Retire) == 1 && call.Retire[0].Selector == burner.Selector {
			retried = true
		}
	}
	if !retried {
		t.Error("the retire was not sent again")
	}
	records, err := keys.loadWithPublishLock()
	if err != nil {
		t.Fatal(err)
	}
	if records[burner.Selector].State != smtpDkimStateRetired {
		t.Errorf("state %s", records[burner.Selector].State)
	}
}

// A publish whose answer never came is sent again with the same selector and key, and nothing new is
// made for the domain in between.
func TestSmtpDkimUnansweredPublishSendsTheSameKey(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{err: errors.New("synthetic transport failure")}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	if _, err := keys.Current(context.Background(), testDkimNetworkDomain); err == nil {
		t.Fatal("signed with no answer")
	}
	first := publisher.lastCall()
	publisher.setErr(nil)
	selector, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	second := publisher.lastCall()
	if second.Publish[0].Selector != first.Publish[0].Selector || !bytes.Equal(second.Publish[0].PublicKey, first.Publish[0].PublicKey) {
		t.Error("a new key in place of the unanswered one")
	}
	if selector.Selector != first.Publish[0].Selector || publisher.callCount() != 2 {
		t.Errorf("%d calls", publisher.callCount())
	}
}

// §14.6: a refused publish, past 64 device selectors, is the send's failed outcome with the server's
// reason, and leaves no key behind.
func TestSmtpDkimRefusedPublishSurfacesItsReason(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	refusal := &SidecarApiError{Route: "POST /smtp/dkim-keys", Status: http.StatusConflict, Code: "dkim_selector_limit"}
	publisher := &smtpDkimTestPublisher{err: refusal}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	_, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if !errors.Is(err, ErrSmtpDkimPublishRefused) {
		t.Fatalf("err %v", err)
	}
	apiErr := &SidecarApiError{}
	if !errors.As(err, &apiErr) || apiErr.Code != "dkim_selector_limit" {
		t.Errorf("no reason in %v", err)
	}
	names, err := secrets.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Errorf("records left: %v", names)
	}
}

// A rotation the server refuses leaves the old selector signing, since DNS still holds it.
func TestSmtpDkimRefusedRotationKeepsTheOldSelector(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	clock := newSmtpDkimTestClock()
	keys := newSmtpDkimTestKeys(secrets, publisher, clock)
	old, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	old.Release()
	clock.advance(91 * 24 * time.Hour)
	publisher.setErr(&SidecarApiError{Route: "POST /smtp/dkim-keys", Status: http.StatusForbidden, Code: "mail_send_denied"})
	kept, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Release()
	if kept.Selector != old.Selector {
		t.Error("a refused rotation dropped the old selector")
	}
	checkSmtpDkimSigns(t, kept)
}

// §5.9: a Locked keychain holds the send, and nothing is made or published.
func TestSmtpDkimLockedKeychainHoldsTheSend(t *testing.T) {
	instance, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	selector, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	instance.Lock()
	if _, err := keys.Current(context.Background(), testDkimTeamDomain); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("err %v", err)
	}
	digest := sha256.Sum256(nil)
	if _, err := selector.SignDkim(digest[:]); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("signed while locked: %v", err)
	}
	if publisher.callCount() != 1 {
		t.Error("published while locked")
	}
}

// Secrets that fail as a damaged keychain does, recording every write.
type smtpDkimFailingSecrets struct {
	stateLock sync.Mutex
	writes    int
}

func (self *smtpDkimFailingSecrets) Get(name string) ([]byte, error) {
	return nil, ErrSidecarStoreFailed
}

func (self *smtpDkimFailingSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writes += 1
	return nil
}

func (self *smtpDkimFailingSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writes += 1
	return nil
}

func (self *smtpDkimFailingSecrets) List(prefix string) ([]string, error) {
	return nil, ErrSidecarStoreFailed
}

// §5's rule (D-CORE-15): a Failed keychain is never read as empty, so nothing is generated, written or
// published, and neither is anything over a record that does not decode.
func TestSmtpDkimFailedKeychainGeneratesNothing(t *testing.T) {
	failing := &smtpDkimFailingSecrets{}
	publisher := &smtpDkimTestPublisher{}
	keys := newSmtpDkimTestKeys(failing, publisher, newSmtpDkimTestClock())
	if _, err := keys.Current(context.Background(), testDkimNetworkDomain); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("err %v", err)
	}
	if failing.writes != 0 || publisher.callCount() != 0 {
		t.Errorf("%d writes, %d calls", failing.writes, publisher.callCount())
	}

	_, secrets := newSmtpDkimTestSecrets(t)
	if err := secrets.Put(smtpDkimSelectorRecordName("aaaaaaaaaaaaaaaaaaaaaaaaaa"), []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	damaged := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	if _, err := damaged.Current(context.Background(), testDkimNetworkDomain); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("err %v", err)
	}
	names, err := secrets.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || publisher.callCount() != 0 {
		t.Errorf("%v after %d calls", names, publisher.callCount())
	}
}

// A key a kill left before its selector record is deleted, never published.
func TestSmtpDkimOrphanKeyIsDeleted(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	if err := secrets.Put(smtpDkimKeyRecordName("aaaaaaaaaaaaaaaaaaaaaaaaaa"), []byte("synthetic orphan key")); err != nil {
		t.Fatal(err)
	}
	publisher := &smtpDkimTestPublisher{}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	selector, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	names, err := secrets.List(smtpDkimKeyRecordPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != smtpDkimKeyRecordName(selector.Selector) {
		t.Errorf("keys %v", names)
	}
}

func TestSmtpDkimRefusesDomainsItCannotSignUnder(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	publisher := &smtpDkimTestPublisher{}
	keys := newSmtpDkimTestKeys(secrets, publisher, newSmtpDkimTestClock())
	for _, domain := range []string{"", "n1.root.example.", "-n1.root.example", "n1..root.example", "n1.root.example>", "a b.example", strings.Repeat("a", 64) + ".example", strings.Repeat("abcdefghi.", 22) + "example"} {
		if _, err := keys.Current(context.Background(), domain); !errors.Is(err, ErrSmtpDkimDomain) {
			t.Errorf("%q: %v", domain, err)
		}
	}
	if publisher.callCount() != 0 {
		t.Error("published a refused domain")
	}
}

// What the published body holds: selectors, domains and public keys, never a private key's octets.
func TestSmtpDkimPublishedBytesHoldOnlyThePublicKey(t *testing.T) {
	_, secrets := newSmtpDkimTestSecrets(t)
	transport := answerWith(200, "")
	transport.answer = func(request *http.Request, body []byte) (*http.Response, error) {
		args := &SmtpDkimKeysArgs{}
		if err := json.Unmarshal(body, args); err != nil {
			return nil, err
		}
		echo, _ := (&smtpDkimTestPublisher{}).SmtpDkimKeys(context.Background(), args)
		encoded, _ := json.Marshal(echo)
		return syntheticResponse(request, 200, string(encoded), nil), nil
	}
	api := newTestSidecarApi(t, transport)
	keys := newSmtpDkimTestKeys(secrets, api, newSmtpDkimTestClock())
	selector, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	request, body := transport.onlyRequest(t)
	if request.Method != "POST" || request.URL.Path != "/smtp/dkim-keys" || request.Header.Get("Authorization") != "Bearer "+testByJwt {
		t.Errorf("%s %s", request.Method, request.URL.Path)
	}
	fields := map[string][]map[string]any{}
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || len(fields["publish"]) != 1 {
		t.Fatalf("body %s", body)
	}
	for name := range fields["publish"][0] {
		if name != "selector" && name != "domain" && name != "public_key" {
			t.Errorf("a %s field", name)
		}
	}
	der, err := secrets.Get(smtpDkimKeyRecordName(selector.Selector))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	private := parsed.(*rsa.PrivateKey)
	for _, secret := range [][]byte{der, private.D.Bytes(), private.Primes[0].Bytes(), private.Primes[1].Bytes()} {
		if bytes.Contains(body, secret) || bytes.Contains(body, []byte(jsonBase64(secret))) {
			t.Error("the body holds private key octets")
		}
	}
}

// encoding/json's form of octets.
func jsonBase64(octets []byte) string {
	encoded, _ := json.Marshal(octets)
	return strings.Trim(string(encoded), `"`)
}

func TestSmtpDkimKeysRouteRefusesWhatItCannotSend(t *testing.T) {
	transport := answerWith(200, `{"published":[],"retired":[]}`)
	api := newTestSidecarApi(t, transport)
	_, secrets := newSmtpDkimTestSecrets(t)
	keys := newSmtpDkimTestKeys(secrets, &smtpDkimTestPublisher{}, newSmtpDkimTestClock())
	selector, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	for _, args := range []*SmtpDkimKeysArgs{
		nil,
		{},
		{Publish: []*SmtpDkimKeyPublish{nil}},
		{Publish: []*SmtpDkimKeyPublish{{Selector: "short", Domain: testDkimNetworkDomain, PublicKey: selector.PublicKey}}},
		{Publish: []*SmtpDkimKeyPublish{{Selector: selector.Selector, Domain: "N1.root.example", PublicKey: selector.PublicKey}}},
		{Publish: []*SmtpDkimKeyPublish{{Selector: selector.Selector, Domain: testDkimNetworkDomain, PublicKey: []byte("not a key")}}},
		{Retire: []*SmtpDkimKeyRetire{{Selector: selector.Selector, Domain: "a b"}}},
	} {
		if _, err := api.SmtpDkimKeys(context.Background(), args); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("%+v: %v", args, err)
		}
	}
	if transport.requestCount() != 0 {
		t.Error("a refused body was sent")
	}
}

// An answer that does not echo every selector named is not the route's.
func TestSmtpDkimKeysRouteRefusesAnAnswerMissingASelector(t *testing.T) {
	transport := answerWith(200, `{"published":[],"retired":["aaaaaaaaaaaaaaaaaaaaaaaaaa"]}`)
	api := newTestSidecarApi(t, transport)
	_, secrets := newSmtpDkimTestSecrets(t)
	keys := newSmtpDkimTestKeys(secrets, &smtpDkimTestPublisher{}, newSmtpDkimTestClock())
	selector, err := keys.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	args := &SmtpDkimKeysArgs{
		Publish: []*SmtpDkimKeyPublish{{Selector: selector.Selector, Domain: testDkimNetworkDomain, PublicKey: selector.PublicKey}},
		Retire:  []*SmtpDkimKeyRetire{{Selector: "aaaaaaaaaaaaaaaaaaaaaaaaaa", Domain: testDkimNetworkDomain}},
	}
	if _, err := api.SmtpDkimKeys(context.Background(), args); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("err %v", err)
	}
	refusing := newTestSidecarApi(t, answerWith(409, `{"code":"dkim_selector_limit"}`))
	_, err = refusing.SmtpDkimKeys(context.Background(), args)
	if apiErr := asSidecarApiError(t, err); apiErr.Status != 409 || apiErr.Code != "dkim_selector_limit" {
		t.Errorf("refusal %+v", apiErr)
	}
}
