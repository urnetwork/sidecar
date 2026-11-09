package sidecar

// CORE-M2-02: the act's order and rule. Presence comes from the log, never the caller; a failed check signs nothing;
// the check covers the act's exact bytes and each posted statement verifies alone; a kill after the check reposts the
// same bytes; MCP and hooks sign only own-resource filings.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An authority as the act reads it: a pin, the presence rule and the live keys, the rest empty.
type testActAuthority struct {
	stateLock sync.Mutex
	pin       *bridge.AuthPin
	// the types the log covers for a signer with a live key
	covered   map[bridge.SignedType]bool
	liveKeys  []*bridge.KeyRow
	sidecars  map[Id]*AclSidecar
	consents  map[[2]Id]bool
	callbacks *CallbackList[SidecarAuthorityEntryFunction]
}

func newTestActAuthority() *testActAuthority {
	chain := sha256.Sum256([]byte("a pin"))
	return &testActAuthority{
		pin:       &bridge.AuthPin{Version: 40, Chain: chain[:]},
		covered:   map[bridge.SignedType]bool{},
		sidecars:  map[Id]*AclSidecar{},
		consents:  map[[2]Id]bool{},
		callbacks: NewCallbackList[SidecarAuthorityEntryFunction](),
	}
}

func (self *testActAuthority) Pin() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return proto.Clone(self.pin).(*bridge.AuthPin)
}

func (self *testActAuthority) Admission(sidecarId Id) *AclSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sidecars[sidecarId]
}

func (self *testActAuthority) MemberDevices(memberId Id) []*AclSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	devices := []*AclSidecar{}
	for _, admission := range self.sidecars {
		if len(admission.TagIds) == 0 && admission.MemberId == memberId {
			devices = append(devices, admission)
		}
	}
	return devices
}

func (self *testActAuthority) Consented(sidecarId Id, memberId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.consents[[2]Id{sidecarId, memberId}]
}

func (self *testActAuthority) CurrentBinding(memberId Id) *bridge.RecoveryBindingRow {
	return nil
}

func (self *testActAuthority) PresenceRequired(statement *SidecarStatement) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < len(self.liveKeys) && self.covered[statement.Type]
}

func (self *testActAuthority) LiveKeys(sidecarId Id) []*bridge.KeyRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*bridge.KeyRow{}, self.liveKeys...)
}

func (self *testActAuthority) Cascade(targetId Id, sinceN uint64) ([]DeviceRevokeItem, error) {
	return nil, nil
}

func (self *testActAuthority) ProposedSince(lostAt time.Time) (uint64, time.Time, bool) {
	return 0, time.Time{}, false
}

func (self *testActAuthority) AddEntryCallback(callback SidecarAuthorityEntryFunction) func() {
	callbackId := self.callbacks.Add(callback)
	return func() {
		self.callbacks.Remove(callbackId)
	}
}

// Applies an entry to every callback, in order.
func (self *testActAuthority) apply(entry *SidecarAuthorityEntry) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.pin = proto.Clone(entry.Pin).(*bridge.AuthPin)
	}()
	for _, callback := range self.callbacks.Get() {
		callback(entry)
	}
}

// POST /network/config/delta as a test scripts it: each post's body is kept, and the next answer is taken from
// answers, ok when it runs out.
type testDeltaApi struct {
	stateLock sync.Mutex
	posts     [][]byte
	// "ok", "lost" (applied, the answer lost) or "refused"
	answers []string
	n       uint64
}

func (self *testDeltaApi) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	request.Body.Close()
	if err != nil {
		return nil, err
	}
	wire := &sidecarConfigDeltaWire{}
	if err := json.Unmarshal(body, wire); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	self.posts = append(self.posts, wire.Signed)
	answer := "ok"
	if 0 < len(self.answers) {
		answer = self.answers[0]
		self.answers = self.answers[1:]
	}
	self.n += 1
	n := self.n
	self.stateLock.Unlock()
	respond := func(status int, value any) *http.Response {
		encoded, _ := json.Marshal(value)
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(encoded)), Header: http.Header{"Content-Type": {"application/json"}}, Request: request}
	}
	chain := sha256.Sum256([]byte{byte(n)})
	switch answer {
	case "lost":
		return nil, errors.New("the answer was lost")
	case "refused":
		return respond(http.StatusForbidden, map[string]any{"error": "The statement fails at the tip.", "code": "config_refused"}), nil
	}
	return respond(http.StatusOK, &sidecarConfigPinReply{N: 100 + n, Chain: chain[:]}), nil
}

// Every post so far.
func (self *testDeltaApi) postsSoFar() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([][]byte{}, self.posts...)
}

// A clock a test moves by hand. Its timers never fire: nothing these tests run waits on one.
type identityTestClock struct {
	stateLock sync.Mutex
	current   time.Time
}

func newIdentityTestClock() *identityTestClock {
	return &identityTestClock{current: time.Date(2026, time.May, 6, 7, 8, 9, 0, time.UTC)}
}

func (self *identityTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

func (self *identityTestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *identityTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return true }
}

func (self *identityTestClock) advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.current = self.current.Add(timeout)
}

// A sidecar with an identity, an installed act authority, and a SidecarApi whose delta route the test scripts, on a
// clock the test moves.
func newActTestSidecar(t *testing.T) (*Sidecar, *testActAuthority, *testDeltaApi) {
	t.Helper()
	sidecar, _, _ := newIdentityTestSidecar(t)
	sidecar.clock = newIdentityTestClock()
	deltaApi := &testDeltaApi{}
	api, err := newSidecarApi(sidecar.settings, deltaApi, sidecar.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt("a-synthetic-client-token-for-the-act-tests")
	sidecar.sidecarApi = api
	authority := newTestActAuthority()
	t.Cleanup(sidecar.InstallAuthority(authority))
	return sidecar, authority, deltaApi
}

// A presence key, P-256 as ecdsa-p256-sha256 holds it, registered live for the act authority.
func addTestPresenceKey(t *testing.T, authority *testActAuthority) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	keyId := sha256.Sum256(publicKey)
	authority.stateLock.Lock()
	authority.liveKeys = append(authority.liveKeys, &bridge.KeyRow{
		KeyId:     keyId[:],
		Alg:       bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256,
		PublicKey: publicKey,
		Purpose:   bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
	})
	authority.covered[bridge.SignedType_SIGNED_OWNER_CONFIRM] = true
	authority.covered[bridge.SignedType_SIGNED_SUSPEND] = true
	authority.stateLock.Unlock()
	return key, keyId[:]
}

// The check a presence key's holder runs: its signature over the countersigned bytes, and the bytes it saw.
func testPresenceCheck(t *testing.T, key *ecdsa.PrivateKey, keyId []byte, seen *[]byte) SidecarPresenceCheck {
	return func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		*seen = bytes.Clone(countersignedBytes)
		digest := sha256.Sum256(countersignedBytes)
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &bridge.WebAuthnEvidence{KeyId: keyId, Signature: signature}, nil
	}
}

// An act of two covered statements, an OwnerConfirm and a Suspend.
func addTestStatements(t *testing.T, act *sidecarAct) {
	t.Helper()
	if err := act.Add(bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{SidecarId: NewId().Bytes()}); err != nil {
		t.Fatal(err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Subject: NewId().Bytes(), SuspendId: NewId().Bytes()}); err != nil {
		t.Fatal(err)
	}
}

// D-TEAM-32: whether presence applies comes from the log, so an act the log covers refuses to run without a check, and
// a caller has no way to say it needs none.
func TestPresenceFromLogNotCaller(t *testing.T) {
	sidecar, authority, deltaApi := newActTestSidecar(t)
	addTestPresenceKey(t, authority)
	act, err := sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	addTestStatements(t, act)
	_, required, err := act.CountersignedBytes()
	if err != nil || !required {
		t.Fatalf("required %v: %v", required, err)
	}
	if _, err := act.Run(t.Context(), nil); !errors.Is(err, ErrSidecarActPresence) {
		t.Fatalf("no check: %v", err)
	}
	if len(deltaApi.postsSoFar()) != 0 {
		t.Error("a statement was posted")
	}

	// the same statements, uncovered once the key is gone, run on the confirmation alone
	authority.stateLock.Lock()
	authority.liveKeys = nil
	authority.stateLock.Unlock()
	uncovered, err := sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	addTestStatements(t, uncovered)
	if _, err := uncovered.Run(t.Context(), nil); err != nil {
		t.Fatalf("no live key: %v", err)
	}
	for _, post := range deltaApi.postsSoFar() {
		signed := &bridge.Signed{}
		proto.Unmarshal(post, signed)
		if signed.GetWebauthn() != nil {
			t.Error("a countersignature the log does not require")
		}
	}
}

// A check that fails, is refused, or answers evidence that does not verify against a live key signs nothing, keeps
// nothing pending and posts nothing.
func TestFailedCheckSignsNothing(t *testing.T) {
	sidecar, authority, deltaApi := newActTestSidecar(t)
	key, keyId := addTestPresenceKey(t, authority)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var seen []byte
	checks := map[string]SidecarPresenceCheck{
		"refused": func([]byte) (*bridge.WebAuthnEvidence, error) { return nil, errors.New("the person refused") },
		"no evidence": func([]byte) (*bridge.WebAuthnEvidence, error) {
			return &bridge.WebAuthnEvidence{}, nil
		},
		"another key's signature": testPresenceCheck(t, otherKey, keyId, &seen),
		"an unknown key_id":       testPresenceCheck(t, key, []byte("not a registered key"), &seen),
	}
	for name, check := range checks {
		act, err := sidecar.newAct(SidecarActConfirmed)
		if err != nil {
			t.Fatal(err)
		}
		addTestStatements(t, act)
		if _, err := act.Run(t.Context(), check); !errors.Is(err, ErrSidecarActPresence) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(deltaApi.postsSoFar()) != 0 {
		t.Error("a statement was posted")
	}
	if pendings, err := sidecar.pendingStatements(); err != nil || len(pendings) != 0 {
		t.Errorf("pending %d: %v", len(pendings), err)
	}
}

// The check is over exactly the act's countersigned bytes, PresenceActBytes over RFC 9162's root of the statements'
// signed bytes, and every statement posted carries a countersignature that verifies alone, as api and every member
// device check it, with its identity signature beside it.
func TestCheckCoversExactBytes(t *testing.T) {
	sidecar, authority, deltaApi := newActTestSidecar(t)
	key, keyId := addTestPresenceKey(t, authority)
	act, err := sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	addTestStatements(t, act)
	var seen []byte
	pins, err := act.Run(t.Context(), testPresenceCheck(t, key, keyId, &seen))
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 {
		t.Fatalf("%d pins", len(pins))
	}
	root, err := bridge.PresenceActRoot(act.digests())
	if err != nil {
		t.Fatal(err)
	}
	identity := sidecar.currentIdentity()
	if want := bridge.PresenceActBytes(identity.SidecarId.Bytes(), 2, root); !bytes.Equal(seen, want) {
		t.Fatal("the check did not cover the act's countersigned bytes")
	}
	posts := deltaApi.postsSoFar()
	if len(posts) != 2 {
		t.Fatalf("%d posts", len(posts))
	}
	publicKey := authority.LiveKeys(identity.SidecarId)[0].GetPublicKey()
	for index, post := range posts {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(post, signed); err != nil {
			t.Fatal(err)
		}
		signedType := bridge.SignedType(signed.GetType())
		purpose, _ := sidecarIdentitySignedPurpose(signedType)
		if err := bridge.VerifyPresenceCountersign(signed, purpose, bridge.SignedKeyAlgEcdsaP256, publicKey); err != nil {
			t.Errorf("statement %d's countersignature: %v", index, err)
		}
		if err := bridge.VerifySigned(signed, purpose, signedType, bridge.SignedKeyAlgEd25519, identity.IdentityPublicKey); err != nil {
			t.Errorf("statement %d's identity signature: %v", index, err)
		}
		if signed.GetWebauthn().GetActIndex() != uint32(index) || signed.GetWebauthn().GetActSize() != 2 {
			t.Errorf("statement %d's act fields: %+v", index, signed.GetWebauthn())
		}
	}
	if pendings, _ := sidecar.pendingStatements(); len(pendings) != 0 {
		t.Errorf("%d still pending after landing", len(pendings))
	}
}

// §5.6's sign row: a kill, or a lost answer, after the check leaves the signed statements pending, and the next start
// posts the very same bytes, never a new signature, until each lands; a refusal drops its statement.
func TestKillAfterCheckRepostsSameBytes(t *testing.T) {
	sidecar, authority, deltaApi := newActTestSidecar(t)
	key, keyId := addTestPresenceKey(t, authority)
	act, err := sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	addTestStatements(t, act)
	deltaApi.answers = []string{"lost"}
	var seen []byte
	if _, err := act.Run(t.Context(), testPresenceCheck(t, key, keyId, &seen)); err == nil || errors.Is(err, ErrSidecarActRefused) {
		t.Fatalf("a lost answer: %v", err)
	}
	pendings, err := sidecar.pendingStatements()
	if err != nil || len(pendings) != 2 {
		t.Fatalf("pending %d: %v", len(pendings), err)
	}
	firstPost := deltaApi.postsSoFar()[0]

	// the restarted daemon posts what is pending, as it was signed
	deltaApi.answers = []string{"ok", "refused"}
	if err := sidecar.PostPendingStatements(t.Context()); err != nil {
		t.Fatal(err)
	}
	posts := deltaApi.postsSoFar()
	if len(posts) != 3 {
		t.Fatalf("%d posts", len(posts))
	}
	reposted := false
	for _, post := range posts[1:] {
		if bytes.Equal(post, firstPost) {
			reposted = true
		}
	}
	if !reposted {
		t.Error("the lost statement was not posted again byte for byte")
	}
	if pendings, _ := sidecar.pendingStatements(); len(pendings) != 0 {
		t.Errorf("%d still pending after landing and a refusal", len(pendings))
	}

	// past its not_after a pending statement is dropped, never posted
	late, err := sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	if err := late.Add(bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: NewId().Bytes()}); err != nil {
		t.Fatal(err)
	}
	deltaApi.answers = []string{"lost"}
	late.Run(t.Context(), nil)
	sidecar.clock.(*identityTestClock).advance(sidecar.settings.StatementTimeout + time.Second)
	before := len(deltaApi.postsSoFar())
	if err := sidecar.PostPendingStatements(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(deltaApi.postsSoFar()) != before {
		t.Error("an expired statement was posted")
	}
}

// D-CORE-13: mode grants nothing. MCP, a hook and an unconfirmed control call sign no admission, OwnerConfirm, veto or
// revocation.
func TestMcpModeCannotSign(t *testing.T) {
	sidecar, _, _ := newActTestSidecar(t)
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		act, err := sidecar.newAct(origin)
		if err != nil {
			t.Fatal(err)
		}
		for signedType, statement := range map[bridge.SignedType]proto.Message{
			bridge.SignedType_SIGNED_OWNER_CONFIRM:  &protocol.OwnerConfirm{SidecarId: NewId().Bytes()},
			bridge.SignedType_SIGNED_SIDECAR_ADMIT:  &protocol.SidecarAdmit{SidecarId: NewId().Bytes()},
			bridge.SignedType_SIGNED_RECOVERY_VETO:  &protocol.RecoveryVeto{ProposalId: make([]byte, 32)},
			bridge.SignedType_SIGNED_SIDECAR_REVOKE: &bridge.SidecarRevoke{SidecarId: NewId().Bytes()},
		} {
			if err := act.Add(signedType, statement); !errors.Is(err, ErrSidecarActMode) {
				t.Errorf("origin %d, type %#x: %v", origin, int32(signedType), err)
			}
		}
	}
}

// §5.8's own-resource filings sign from any mode.
func TestOwnResourceFilingFromAnyMode(t *testing.T) {
	sidecar, _, deltaApi := newActTestSidecar(t)
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed, SidecarActConfirmed} {
		act, err := sidecar.newAct(origin)
		if err != nil {
			t.Fatal(err)
		}
		if err := act.Add(bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{GrantId: NewId().Bytes()}); err != nil {
			t.Fatalf("origin %d: %v", origin, err)
		}
		if _, err := act.Run(t.Context(), nil); err != nil {
			t.Fatalf("origin %d: %v", origin, err)
		}
	}
	if len(deltaApi.postsSoFar()) != 4 {
		t.Errorf("%d posts", len(deltaApi.postsSoFar()))
	}
}

// Every statement but an own-resource filing needs the person's confirmation, and a statement with no header field
// or a type the identity key does not sign as a statement is refused before anything is built.
func TestOtherStatementsNeedConfirm(t *testing.T) {
	sidecar, _, _ := newActTestSidecar(t)
	act, err := sidecar.newAct(SidecarActHook)
	if err != nil {
		t.Fatal(err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: NewId().Bytes()}); !errors.Is(err, ErrSidecarActMode) {
		t.Errorf("a hook's RepoCreate: %v", err)
	}
	confirmed, err := sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmed.Add(bridge.SignedType_SIGNED_READER_KEY, &protocol.ReaderKey{}); !errors.Is(err, ErrSidecarSignRefused) {
		t.Errorf("a ReaderKey is no statement: %v", err)
	}
	if err := confirmed.Add(bridge.SignedType_SIGNED_OWNER_CONFIRM, &bridge.AuthPin{}); !errors.Is(err, ErrSidecarSignRefused) {
		t.Errorf("a message with no header: %v", err)
	}
	if _, err := confirmed.Run(t.Context(), nil); !errors.Is(err, ErrSidecarActState) {
		t.Errorf("an empty act: %v", err)
	}
	if _, err := (&Sidecar{}).newAct(SidecarActConfirmed); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Errorf("no authority: %v", err)
	}
}
