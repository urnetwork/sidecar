//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M3-09's root half on a fake authenticator with fixture keys, the act tests' sidecar and its delta route: a first
// presence key registers on a confirmation alone, carrying its own proof; a harness, an MCP call or an unconfirmed call
// registers nothing; a failed or refused prompt signs nothing and takes the new key off the authenticator; a second key
// from a device holding a live one is countersigned; a key is removed only from a device with a live key of its own;
// the daemon's prompt yields a presence decision; and each act asks the authenticator afresh.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An authenticator in memory: fixture keys of one profile, each made by Register, and every call counted.
type testPresenceProvider struct {
	t         testing.TB
	alg       bridge.KeyAlg
	stateLock sync.Mutex
	keyIdKeys map[string]*testPresenceKey
	// Register's and Assert's calls
	registerCount int
	assertCount   int
	// what Assert answers instead of an assertion, nil to assert
	refuse  error
	removed [][]byte
}

func newTestPresenceProvider(t testing.TB, alg bridge.KeyAlg) *testPresenceProvider {
	return &testPresenceProvider{t: t, alg: alg, keyIdKeys: map[string]*testPresenceKey{}}
}

func (self *testPresenceProvider) Register(ctx context.Context) (*PresenceKeyHandle, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.registerCount += 1
	key := newTestPresenceKey(self.t, fmt.Sprintf("provider key %d", self.registerCount), self.alg)
	self.keyIdKeys[hex.EncodeToString(key.keyId)] = key
	return &PresenceKeyHandle{KeyId: bytes.Clone(key.keyId), Alg: key.alg, PublicKey: bytes.Clone(key.publicKey)}, nil
}

func (self *testPresenceProvider) Holds(keyId []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	_, ok := self.keyIdKeys[hex.EncodeToString(keyId)]
	return ok
}

func (self *testPresenceProvider) Assert(ctx context.Context, keyId []byte, message []byte) (*bridge.WebAuthnEvidence, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.assertCount += 1
	if self.refuse != nil {
		return nil, self.refuse
	}
	key, ok := self.keyIdKeys[hex.EncodeToString(keyId)]
	if !ok {
		return nil, errors.New("no such key")
	}
	if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
		evidence, signature := key.assert(self.t, testGoodPresenceAssertion(), message)
		evidence.KeyId = bytes.Clone(keyId)
		evidence.Signature = signature
		return evidence, nil
	}
	digest := sha256.Sum256(message)
	return &bridge.WebAuthnEvidence{KeyId: bytes.Clone(keyId), Signature: key.signDigest(self.t, digest[:])}, nil
}

func (self *testPresenceProvider) Remove(keyId []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.keyIdKeys, hex.EncodeToString(keyId))
	self.removed = append(self.removed, bytes.Clone(keyId))
	return nil
}

// The key of keyId as the provider holds it, its row as a state registered to memberId by signerId would hold it.
func (self *testPresenceProvider) row(keyId []byte, memberId Id, signerId Id) *bridge.KeyRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := self.keyIdKeys[hex.EncodeToString(keyId)]
	return &bridge.KeyRow{
		KeyId: bytes.Clone(key.keyId), MemberId: memberId.Bytes(), Alg: key.alg, PublicKey: bytes.Clone(key.publicKey),
		Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: signerId.Bytes(), At: 3,
	}
}

func (self *testPresenceProvider) counts() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.registerCount, self.assertCount
}

// The act authority with live keys per registering device, as §7.9's state keeps them.
type testPresenceAuthority struct {
	*testActAuthority
	keysLock       sync.Mutex
	sidecarIdKeys  map[Id][]*bridge.KeyRow
	coveredByLives bool
}

func (self *testPresenceAuthority) LiveKeys(sidecarId Id) []*bridge.KeyRow {
	self.keysLock.Lock()
	defer self.keysLock.Unlock()
	return slices.Clone(self.sidecarIdKeys[sidecarId])
}

func (self *testPresenceAuthority) PresenceRequired(statement *SidecarStatement) bool {
	self.keysLock.Lock()
	defer self.keysLock.Unlock()
	return 0 < len(self.sidecarIdKeys[statement.SignerId]) && self.covered[statement.Type]
}

func (self *testPresenceAuthority) give(sidecarId Id, row *bridge.KeyRow) {
	self.keysLock.Lock()
	defer self.keysLock.Unlock()
	self.sidecarIdKeys[sidecarId] = append(self.sidecarIdKeys[sidecarId], row)
}

// A consented device of its member, a second device of the member, the per-device authority and a fake authenticator.
type testPresenceWorld struct {
	t         *testing.T
	sidecar   *Sidecar
	authority *testPresenceAuthority
	provider  *testPresenceProvider
	memberId  Id
	sidecarId Id
	otherId   Id
}

func newTestPresenceWorld(t *testing.T, alg bridge.KeyAlg) *testPresenceWorld {
	t.Helper()
	sidecar, actAuthority, _ := newActTestSidecar(t)
	authority := &testPresenceAuthority{testActAuthority: actAuthority, sidecarIdKeys: map[Id][]*bridge.KeyRow{}}
	t.Cleanup(sidecar.InstallAuthority(authority))
	world := &testPresenceWorld{
		t:         t,
		sidecar:   sidecar,
		authority: authority,
		provider:  newTestPresenceProvider(t, alg),
		memberId:  NewId(),
		sidecarId: sidecar.currentIdentity().SidecarId,
		otherId:   NewId(),
	}
	actAuthority.stateLock.Lock()
	for _, sidecarId := range []Id{world.sidecarId, world.otherId} {
		actAuthority.sidecars[sidecarId] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), MemberId: world.memberId.Bytes()}, MemberId: world.memberId}
		actAuthority.consents[[2]Id{sidecarId, world.memberId}] = true
	}
	actAuthority.covered[bridge.SignedType_SIGNED_KEY_REGISTER] = true
	actAuthority.covered[bridge.SignedType_SIGNED_KEY_REVOKE] = true
	actAuthority.stateLock.Unlock()
	return world
}

// Registers a key of the provider's as a live one of sidecarId's, outside any act.
func (self *testPresenceWorld) liveKey(sidecarId Id) []byte {
	self.t.Helper()
	handle, err := self.provider.Register(self.t.Context())
	if err != nil {
		self.t.Fatal(err)
	}
	self.authority.give(sidecarId, self.provider.row(handle.KeyId, self.memberId, sidecarId))
	return handle.KeyId
}

// A first key registers on a confirmation alone: its KeyRegister names the member, carries the key's own proof over
// the bytes the identity key signed, and no countersignature, since no live key covered the act.
func TestFirstKeyOnTtyOnly(t *testing.T) {
	for _, alg := range []bridge.KeyAlg{bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256} {
		world := newTestPresenceWorld(t, alg)
		key, err := world.sidecar.RegisterPresenceKey(t.Context(), world.provider, SidecarActConfirmed, nil)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		posted := postedStatements(t, world.sidecar)
		if len(posted) != 1 || posted[0].GetType() != uint32(bridge.SignedType_SIGNED_KEY_REGISTER) {
			t.Fatalf("%s: %d statements posted", alg, len(posted))
		}
		register := &protocol.KeyRegister{}
		if err := proto.Unmarshal(posted[0].GetBody(), register); err != nil {
			t.Fatal(err)
		}
		if err := VerifyPresenceRegistration(register, posted[0]); err != nil {
			t.Errorf("%s: the key's own proof: %v", alg, err)
		}
		identity := world.sidecar.currentIdentity()
		if err := bridge.VerifySigned(posted[0], bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_KEY_REGISTER, bridge.SignedKeyAlgEd25519, identity.IdentityPublicKey); err != nil {
			t.Errorf("%s: the identity signature: %v", alg, err)
		}
		if posted[0].GetWebauthn() != nil || !bytes.Equal(register.GetMemberId(), world.memberId.Bytes()) ||
			!bytes.Equal(register.GetKeyId(), key.KeyId) || register.GetPurpose() != bridge.KeyPurpose_KEY_PURPOSE_PRESENCE ||
			register.GetNotAfter() <= world.sidecar.clock.Now().UnixMilli() {
			t.Errorf("%s: the KeyRegister: %+v", alg, register)
		}
	}
}

// Never harness, nor MCP, nor an unconfirmed call: nothing is asked of the authenticator and nothing is signed.
func TestHarnessCannotRegisterKey(t *testing.T) {
	world := newTestPresenceWorld(t, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	for _, origin := range []SidecarActOrigin{SidecarActHook, SidecarActMcp, SidecarActUnconfirmed} {
		if _, err := world.sidecar.RegisterPresenceKey(t.Context(), world.provider, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	if registerCount, _ := world.provider.counts(); registerCount != 0 || len(postedStatements(t, world.sidecar)) != 0 {
		t.Error("a key was made or a statement signed")
	}
}

// A refused key proof, and a refused countersignature, each sign nothing, and the new key is taken off the
// authenticator.
func TestFailedPromptSignsNothing(t *testing.T) {
	world := newTestPresenceWorld(t, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	world.provider.refuse = errors.New("the person cancelled")
	if _, err := world.sidecar.RegisterPresenceKey(t.Context(), world.provider, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarActPresence) {
		t.Errorf("a refused proof: %v", err)
	}
	if len(postedStatements(t, world.sidecar)) != 0 || len(world.provider.removed) != 1 {
		t.Fatalf("posted %d, removed %d", len(postedStatements(t, world.sidecar)), len(world.provider.removed))
	}
	world.provider.refuse = nil
	world.liveKey(world.sidecarId)
	refused := func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		return nil, errors.New("no biometry")
	}
	if _, err := world.sidecar.RegisterPresenceKey(t.Context(), world.provider, SidecarActConfirmed, refused); !errors.Is(err, ErrSidecarActPresence) {
		t.Errorf("a refused countersignature: %v", err)
	}
	if len(postedStatements(t, world.sidecar)) != 0 || len(world.provider.removed) != 2 {
		t.Errorf("posted %d, removed %d", len(postedStatements(t, world.sidecar)), len(world.provider.removed))
	}
}

// A device holding a live presence key registers a second one under that key's countersignature, from the daemon's
// prompt.
func TestSecondKeyIsCountersigned(t *testing.T) {
	world := newTestPresenceWorld(t, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	liveKeyId := world.liveKey(world.sidecarId)
	prompt := NewPresencePrompt(world.sidecar, world.provider)
	if _, err := world.sidecar.RegisterPresenceKey(t.Context(), world.provider, SidecarActConfirmed, prompt); err != nil {
		t.Fatal(err)
	}
	posted := postedStatements(t, world.sidecar)
	if len(posted) != 1 || posted[0].GetWebauthn() == nil || !bytes.Equal(posted[0].GetWebauthn().GetKeyId(), liveKeyId) {
		t.Fatalf("the registration carries no countersignature of the live key: %+v", posted)
	}
	if err := VerifyPresenceCountersignature(posted[0], bridge.SignedPurposeAuthority, world.provider.row(liveKeyId, world.memberId, world.sidecarId)); err != nil {
		t.Errorf("the countersignature: %v", err)
	}
}

// §16.6's remove row: a presence key is removed only from a device that registered a live one of its own, under its
// countersignature; and only a key of the member's.
func TestRemoveNeedsOwnLiveKey(t *testing.T) {
	world := newTestPresenceWorld(t, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	otherKeyId := world.liveKey(world.otherId)
	if err := world.sidecar.RevokePresenceKey(t.Context(), otherKeyId, world.provider, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalNotEligible) {
		t.Errorf("a device with no live key of its own: %v", err)
	}
	if err := world.sidecar.RevokePresenceKey(t.Context(), []byte("no such key"), world.provider, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalUnknown) {
		t.Errorf("a key that is not the member's: %v", err)
	}
	world.liveKey(world.sidecarId)
	if err := world.sidecar.RevokePresenceKey(t.Context(), otherKeyId, world.provider, SidecarActHook, nil); !errors.Is(err, ErrSidecarActMode) {
		t.Errorf("a hook's removal: %v", err)
	}
	if err := world.sidecar.RevokePresenceKey(t.Context(), otherKeyId, world.provider, SidecarActConfirmed, NewPresencePrompt(world.sidecar, world.provider)); err != nil {
		t.Fatal(err)
	}
	posted := postedStatements(t, world.sidecar)
	if len(posted) != 1 || posted[0].GetType() != uint32(bridge.SignedType_SIGNED_KEY_REVOKE) || posted[0].GetWebauthn() == nil {
		t.Fatalf("the removal: %+v", posted)
	}
	revoke := &protocol.KeyRevoke{}
	if err := proto.Unmarshal(posted[0].GetBody(), revoke); err != nil || !bytes.Equal(revoke.GetKeyId(), otherKeyId) {
		t.Errorf("the KeyRevoke names %x, %v", revoke.GetKeyId(), err)
	}
	if world.provider.Holds(otherKeyId) {
		t.Error("the removed key stays on this host's authenticator")
	}
	keys, err := world.sidecar.PresenceKeys(world.provider)
	if err != nil || len(keys) != 2 {
		t.Fatalf("%d keys, %v", len(keys), err)
	}
}

// FS-28's presence case: on a host holding the member's key, the daemon's prompt signs this sidecar's own request as a
// presence decision, which the per-use profile verifies, never needing harness_ok.
func TestPromptYieldsChannelPresence(t *testing.T) {
	world := newTestPresenceWorld(t, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	keyId := world.liveKey(world.sidecarId)
	approverWorld := &testApproverWorld{t: t, sidecar: world.sidecar, memberId: world.memberId, vaultId: NewId()}
	approverWorld.log = &testApproverLog{logIds: []Id{approverWorld.vaultId}}
	approverWorld.approver = NewApprovalApprover(world.sidecar, approverWorld.log)
	request := approverWorld.put(world.sidecarId, testApproverDnsSet(t, "198.51.100.7"), "")
	daemon := &Daemon{}
	if daemon.PresencePrompt(world.sidecar) != nil {
		t.Error("a prompt with no authenticator set")
	}
	daemon.SetPresenceProvider(world.provider)
	err := approverWorld.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, daemon.PresencePrompt(world.sidecar))
	if err != nil {
		t.Fatal(err)
	}
	decision := approverWorld.lastDecision()
	if decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE) || !bytes.Equal(decision.Signed.GetKeyId(), keyId) {
		t.Errorf("the decision: channel %d, key %x", decision.Decision.GetChannel(), decision.Signed.GetKeyId())
	}
	if err := VerifyPresenceUse(decision.Signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, world.provider.row(keyId, world.memberId, world.sidecarId), nil); err != nil {
		t.Errorf("the decision does not verify: %v", err)
	}
}

// §16.6's countersign row: each act asks the authenticator afresh, one assertion per prompt, none reused across acts.
func TestFreshContextEachAct(t *testing.T) {
	world := newTestPresenceWorld(t, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	world.liveKey(world.sidecarId)
	world.authority.stateLock.Lock()
	world.authority.covered[bridge.SignedType_SIGNED_OWNER_CONFIRM] = true
	world.authority.stateLock.Unlock()
	prompt := NewPresencePrompt(world.sidecar, world.provider)
	_, before := world.provider.counts()
	for range 2 {
		act, err := world.sidecar.newAct(SidecarActConfirmed)
		if err != nil {
			t.Fatal(err)
		}
		if err := act.Add(bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{SidecarId: world.otherId.Bytes()}); err != nil {
			t.Fatal(err)
		}
		if _, err := act.Run(t.Context(), prompt); err != nil {
			t.Fatal(err)
		}
	}
	if _, after := world.provider.counts(); after-before != 2 {
		t.Errorf("%d assertions for two acts", after-before)
	}
	for _, signed := range postedStatements(t, world.sidecar) {
		if signed.GetWebauthn() == nil {
			t.Error("an act signed without its countersignature")
		}
	}
}
