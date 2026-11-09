//go:build !sidecar_http && !js

package sidecar

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

// §22.5's §18 row at the core (CORE-M8-01): an sdk host's TokenSource refreshes once it holds the core's signer, and
// only then does D-CORE-8's refresher stand down; its tokens are re-sealed and installed, its logouts end only the
// generation they name, and a re-pair keeps the sidecar_id.

// A host token source as an sdk host's Api session would be: a token, its callbacks, the signer it was handed, and its
// logouts.
type testTokenSource struct {
	stateLock       sync.Mutex
	byJwt           string
	takesSigner     bool
	signer          SidecarDpopSigner
	tokenCallbacks  *CallbackList[func(byJwt string)]
	logoutCallbacks *CallbackList[func(byJwt string, cause string)]
}

func newTestTokenSource(takesSigner bool) *testTokenSource {
	return &testTokenSource{
		takesSigner:     takesSigner,
		tokenCallbacks:  NewCallbackList[func(byJwt string)](),
		logoutCallbacks: NewCallbackList[func(byJwt string, cause string)](),
	}
}

func (self *testTokenSource) ByJwt() (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.byJwt == "" {
		return "", errors.New("no token yet")
	}
	return self.byJwt, nil
}

func (self *testTokenSource) AddByJwtCallback(callback func(byJwt string)) func() {
	callbackId := self.tokenCallbacks.Add(callback)
	return func() { self.tokenCallbacks.Remove(callbackId) }
}

func (self *testTokenSource) SetDpopSigner(signer SidecarDpopSigner) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.takesSigner {
		return errors.New("this source refreshes no sidecar token")
	}
	self.signer = signer
	return nil
}

func (self *testTokenSource) AddLogoutCallback(callback func(byJwt string, cause string)) func() {
	callbackId := self.logoutCallbacks.Add(callback)
	return func() { self.logoutCallbacks.Remove(callbackId) }
}

// The host refreshed: its new token goes to every callback.
func (self *testTokenSource) refreshed(byJwt string) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.byJwt = byJwt
	}()
	for _, callback := range self.tokenCallbacks.Get() {
		callback(byJwt)
	}
}

// The host found a confirmed rejection of byJwt current.
func (self *testTokenSource) loggedOut(byJwt string, cause string) {
	for _, callback := range self.logoutCallbacks.Get() {
		callback(byJwt, cause)
	}
}

// The signer it holds.
func (self *testTokenSource) heldSigner() SidecarDpopSigner {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.signer
}

// A host whose TokenSource is source.
type testTokenSourceHost struct {
	testSidecarHost
	source SidecarTokenSource
}

func (self *testTokenSourceHost) TokenSource() SidecarTokenSource {
	return self.source
}

// An enrolled sidecar on a host with source, its first generation running.
func newTokenSourceTestSidecar(t *testing.T, source *testTokenSource) (*Sidecar, *testEnrollment) {
	t.Helper()
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar, err := NewSidecar(context.Background(), &testTokenSourceHost{testSidecarHost: testSidecarHost{store: instance.Store(&enrollment.networkId)}, source: source}, nil, testSidecarSettings(platform))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sidecarTestTimeout)
		defer cancel()
		sidecar.CloseAndWait(ctx)
	})
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	for {
		number, changed := sidecar.runningGenerationNumber.Get()
		if number == 1 {
			break
		}
		<-changed
	}
	return sidecar, enrollment
}

// The public key a DPoP proof's header names.
func testDpopProofKey(t *testing.T, proof string) ed25519.PublicKey {
	t.Helper()
	header, err := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	decoded := &struct {
		Jwk struct {
			X string `json:"x"`
		} `json:"jwk"`
	}{}
	if err := json.Unmarshal(header, decoded); err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawURLEncoding.DecodeString(decoded.Jwk.X)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The trap: the source refreshes only with a signer, so the core hands its ClientKey's signer over first and stands its
// own refresher down only once the source took it. A source that takes none leaves the core refreshing.
func TestSignerInstalledBeforeRefresherOff(t *testing.T) {
	source := newTestTokenSource(true)
	sidecar, enrollment := newTokenSourceTestSidecar(t, source)
	signer := source.heldSigner()
	if signer == nil {
		t.Fatal("the core stood down with no signer handed over")
	}
	proof, err := signer("GET", "https://api.example/auth/refresh", dpopAth(enrollment.byJwt))
	if err != nil {
		t.Fatal(err)
	}
	if !testDpopProofKey(t, proof).Equal(enrollment.keys.clientPublicKey()) {
		t.Error("the handed signer is not this generation's ClientKey")
	}
	if manager := sidecar.runningGeneration().tokenManager.Load(); manager == nil || !manager.args.HostRefreshes {
		t.Fatal("the core's refresher did not stand down")
	}
	exported, err := sidecar.DpopSigner()
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := exported("POST", "https://api.example/network/auth-client", dpopAth(enrollment.byJwt)); err != nil ||
		!testDpopProofKey(t, proof).Equal(enrollment.keys.clientPublicKey()) {
		t.Errorf("DpopSigner: %v", err)
	}

	refusing := newTestTokenSource(false)
	refusingSidecar, _ := newTokenSourceTestSidecar(t, refusing)
	if manager := refusingSidecar.runningGeneration().tokenManager.Load(); manager == nil || manager.args.HostRefreshes {
		t.Fatal("the core stood down for a source that took no signer")
	}
}

// The host's refreshed token is re-sealed in the keychain and installed, and another client's is kept nowhere.
func TestHostTokenReSealedAndInstalled(t *testing.T) {
	source := newTestTokenSource(true)
	sidecar, enrollment := newTokenSourceTestSidecar(t, source)
	refreshed := testClientTokenOf(enrollment.networkId, enrollment.clientId)
	if refreshed == enrollment.byJwt {
		t.Fatal("the synthetic tokens collide")
	}
	source.refreshed(refreshed)
	if kept, err := loadSidecarByJwt(enrollment.secrets); err != nil || kept != refreshed || sidecar.sidecarApi.currentByJwt() != refreshed {
		t.Fatalf("the refreshed token: kept %v, installed %v", kept == refreshed, sidecar.sidecarApi.currentByJwt() == refreshed)
	}
	source.refreshed(testClientTokenOf(enrollment.networkId, NewId()))
	if kept, _ := loadSidecarByJwt(enrollment.secrets); kept != refreshed || sidecar.sidecarApi.currentByJwt() != refreshed {
		t.Error("another client's token was kept")
	}
}

// A host logout of this generation's token ends it Unenrolled, session_revoked as session_ended and any other as
// parent_lost, identity kept; a released logout of an older generation's token is dropped.
func TestHostLogoutEndsOnlyItsGeneration(t *testing.T) {
	for _, cause := range []string{"session_revoked", ""} {
		source := newTestTokenSource(true)
		sidecar, enrollment := newTokenSourceTestSidecar(t, source)
		source.loggedOut(testClientTokenOf(enrollment.networkId, NewId()), cause)
		if status := sidecar.Status(); status.State != SidecarStateOnline {
			t.Fatalf("another client's logout moved the sidecar to %s", status.State)
		}
		source.loggedOut(enrollment.byJwt, cause)
		want := SidecarReasonParentLost
		if cause == "session_revoked" {
			want = SidecarReasonSessionEnded
		}
		awaitSidecarStatus(t, sidecar, func(status SidecarStatus) bool {
			return status.State == SidecarStateUnenrolled && status.Reason == want
		})
		if identity := sidecar.currentIdentity(); identity == nil || identity.SidecarId != enrollment.sidecarId {
			t.Fatal("a host logout dropped the identity")
		}
	}
}

// A child minted for an sdk host (§5.6): the mint names this generation's ClientKey, nothing is kept without both marks
// and the child is removed, and a re-pair binds generation 2 under the same sidecar_id while generation 1's released
// logout is dropped.
func TestChildEnrollmentAndRepair(t *testing.T) {
	world := newTestEnrollWorld(t)
	mints := 0
	var mintedKeys [][]byte
	adminRefused := false
	mint := func(ctx context.Context, clientPublicKey []byte) (*SidecarAuthClientResult, error) {
		mints += 1
		mintedKeys = append(mintedKeys, clientPublicKey)
		clientId := NewId()
		return &SidecarAuthClientResult{
			ByClientJwt:  testClientTokenOf(world.api.networkId, clientId),
			ClientId:     clientId,
			AdminRefused: adminRefused,
			StrictExp:    true,
		}, nil
	}
	if err := world.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{MintChild: mint}); !errors.Is(err, ErrSidecarEnrollNotAdminRefused) {
		t.Fatalf("a child without admin_refused: %v", err)
	}
	if len(world.instance.Networks()) != 0 || len(world.api.removed) != 1 {
		t.Fatalf("a refused child kept something or was not removed: records %d, removed %d", len(world.instance.Networks()), len(world.api.removed))
	}
	if err := world.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{ChildJwt: "a-synthetic-child-token"}); !errors.Is(err, ErrSidecarEnrollChild) {
		t.Fatalf("a bare child token: %v", err)
	}

	adminRefused = true
	if err := world.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{MintChild: mint}); err != nil {
		t.Fatal(err)
	}
	world.platform.connected.Set(true)
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 1))
	first := world.sidecar.currentIdentity()
	if first.Generation != 1 || string(first.ClientPublicKey) != string(mintedKeys[1]) {
		t.Fatal("the child was not minted for this generation's ClientKey")
	}
	records := world.instance.Networks()
	if len(records) != 1 || !records[0].Child {
		t.Fatalf("the record is not a child's: %+v", records)
	}
	firstToken, _ := loadSidecarByJwt(world.instance.secrets(first.NetworkId, sidecarCoreSecretsNamespace))
	opened := world.platform.awaitOpened(t, 1)
	world.sidecar.runningGeneration().tokenManager.Load().end(SidecarReasonParentLost)
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateUnenrolled, 1))
	<-opened.closed

	if err := world.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{MintChild: mint}); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 2))
	second := world.sidecar.currentIdentity()
	if second.SidecarId != first.SidecarId || second.Generation != 2 || second.ClientId == first.ClientId {
		t.Fatalf("the re-pair: %+v", second)
	}
	// the first generation's logout, released late, is dropped
	world.sidecar.tokenRefused(1, SidecarReasonRefused)
	if status := world.sidecar.Status(); status.State != SidecarStateOnline || status.Generation != 2 {
		t.Fatalf("an older generation's logout moved the sidecar: %+v", status)
	}
	if firstToken == "" || len(world.api.removed) != 2 {
		t.Errorf("the first child was not removed at the re-pair: removed %d", len(world.api.removed))
	}
}
