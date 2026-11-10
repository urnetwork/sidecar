package sidecar

// CORE-M2-05's sealing (§22.5's §5 row, D-CORE-14, R-CORE-15, FS-22's device half): keychain.wrap's HPKE copy opens
// under its own membership's code and no other, in its own network and no other, even with a copy of the whole state
// directory; a rotation re-seals it; the sealer brings it to the member's current binding at every change, a void
// included, with no copy while none is current, and records each span, which a void's alarm names; a rotation signs
// the binding only on the member's consented device after a person's confirmation, keeps no code, and leaves the old
// code opening only what was sealed to it before.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The keys of a code drawn from entropy filled with fill.
func testRecoveryKeys(t *testing.T, fill byte) *RecoveryKeys {
	t.Helper()
	code, err := NewRecoveryCode(bytes.NewReader(countingBytes(fill, recoveryCodeByteCount)))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := code.Keys()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// The config repo's keys as a test holds them: one generation.
type testConfigKeys struct {
	key *EvsRepoKey
}

func (self *testConfigKeys) CurrentConfigKey(ctx context.Context) (*EvsRepoKey, error) {
	return self.key, nil
}

func (self *testConfigKeys) ConfigKeyAt(generation uint64) *EvsRepoKey {
	if self.key.Generation() == generation {
		return self.key
	}
	return nil
}

// The copy holds every root U opens, opens under the code it was sealed to and no other, and goes when no binding is
// current.
func TestRecoveryCopyOpensUnderItsCodeAlone(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	keys, otherKeys := testRecoveryKeys(t, 0x10), testRecoveryKeys(t, 0x50)
	if _, _, err := instance.openRecoveryRoots(testNetworkId, keys); !errors.Is(err, ErrRecoveryCopyAbsent) {
		t.Fatalf("before any seal: %v", err)
	}
	if err := instance.sealRecoveryCopy(testNetworkId, keys.KeySha256(), keys.XwingPublicKey()); err != nil {
		t.Fatal(err)
	}
	wrap, err := instance.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	want, err := instance.openRoots(wrap)
	if err != nil {
		t.Fatal(err)
	}
	roots, newest, err := instance.openRecoveryRoots(testNetworkId, keys)
	if err != nil {
		t.Fatal(err)
	}
	if newest != wrap.roots[0].generation || len(roots) != len(want) || !bytes.Equal(roots[newest], want[newest]) {
		t.Errorf("the code opened %d roots, newest %d", len(roots), newest)
	}
	if _, _, err := instance.openRecoveryRoots(testNetworkId, otherKeys); !errors.Is(err, ErrRecoveryCopyKey) {
		t.Errorf("another code: %v", err)
	}
	if err := instance.sealRecoveryCopy(testNetworkId, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := instance.openRecoveryRoots(testNetworkId, keys); !errors.Is(err, ErrRecoveryCopyAbsent) {
		t.Errorf("after the copy went: %v", err)
	}
}

// D-CORE-14, §22.5's §5 row: one R_n per network, so one membership's code opens its own network's roots and nothing
// of another network's, with a copy of the whole state directory in hand and no U, even when the copy's bytes are
// moved between the two networks' files.
func TestRecoveryCodeOpensNoOtherNetwork(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	otherNetworkId, _ := IdFromBytes(countingBytes(0x71, 16))
	enrollTestNetwork(t, instance, otherNetworkId)
	keys, otherKeys := testRecoveryKeys(t, 0x10), testRecoveryKeys(t, 0x50)
	if err := instance.sealRecoveryCopy(testNetworkId, keys.KeySha256(), keys.XwingPublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := instance.sealRecoveryCopy(otherNetworkId, otherKeys.KeySha256(), otherKeys.XwingPublicKey()); err != nil {
		t.Fatal(err)
	}
	wrap, err := instance.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	want, err := instance.openRoots(wrap)
	if err != nil {
		t.Fatal(err)
	}

	// the whole state directory, copied, behind a key store that holds nothing: no U opens it
	copied := NewSidecarMemoryBackend()
	for path, content := range backendSnapshot(t, backend) {
		putBackendFile(t, copied, path, content)
	}
	thief := newInstanceOn(t, copied, newFakeKeyStore())
	roots, newest, err := thief.openRecoveryRoots(testNetworkId, keys)
	if err != nil || !bytes.Equal(roots[newest], want[newest]) {
		t.Fatalf("the code does not open its own network: %v", err)
	}
	if _, _, err := thief.openRecoveryRoots(otherNetworkId, keys); !errors.Is(err, ErrRecoveryCopyKey) {
		t.Errorf("the code on another network: %v", err)
	}
	if _, _, err := thief.openRecoveryRoots(testNetworkId, otherKeys); !errors.Is(err, ErrRecoveryCopyKey) {
		t.Errorf("another network's code here: %v", err)
	}
	// the other network's roots are another secret entirely
	otherRoots, otherNewest, err := thief.openRecoveryRoots(otherNetworkId, otherKeys)
	if err != nil || bytes.Equal(otherRoots[otherNewest], roots[newest]) {
		t.Fatalf("the networks share a root, or the other code fails: %v", err)
	}
	// this network's copy moved into the other network's file opens nothing there: the seal binds the network
	otherWrap, err := thief.readKeychainWrap(otherNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	wrapNow, err := thief.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	otherWrap.recovery = wrapNow.recovery
	putBackendFile(t, copied, keychainWrapPath(otherNetworkId), otherWrap.encode())
	if _, _, err := thief.openRecoveryRoots(otherNetworkId, keys); !errors.Is(err, ErrRecoveryCopyKey) {
		t.Errorf("a moved copy: %v", err)
	}
}

// `ur keychain rotate` re-seals the copy with the roots, so the code opens the new root once the old ones are gone,
// and only it.
func TestRotationResealsTheRecoveryCopy(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	keys := testRecoveryKeys(t, 0x10)
	if err := instance.sealRecoveryCopy(testNetworkId, keys.KeySha256(), keys.XwingPublicKey()); err != nil {
		t.Fatal(err)
	}
	before, beforeNewest, err := instance.openRecoveryRoots(testNetworkId, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	wrap, err := instance.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	want, err := instance.openRoots(wrap)
	if err != nil {
		t.Fatal(err)
	}
	roots, newest, err := instance.openRecoveryRoots(testNetworkId, keys)
	if err != nil {
		t.Fatal(err)
	}
	if newest != beforeNewest+1 || len(roots) != 1 || !bytes.Equal(roots[newest], want[newest]) || bytes.Equal(roots[newest], before[beforeNewest]) {
		t.Errorf("after a rotation the code opens %d roots, newest %d", len(roots), newest)
	}
	sealedTo, err := instance.recoveryCopyKeySha256(testNetworkId)
	if err != nil || !bytes.Equal(sealedTo, keys.KeySha256()) {
		t.Errorf("the copy moved off its binding: %v", err)
	}
}

// The binding the copy is sealed to now, in hex, empty for none.
func (self *revokeTestWorld) sealedTo(t *testing.T) string {
	t.Helper()
	keySha256, err := self.instance.recoveryCopyKeySha256(self.sidecar.currentIdentity().NetworkId)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(keySha256)
}

// Sets the member's binding in effect and applies the entry that did it.
func (self *revokeTestWorld) bind(keys *RecoveryKeys, restored bool, edit func(entry *SidecarAuthorityEntry)) *SidecarAuthorityEntry {
	self.authority.edit(func() {
		if keys == nil {
			delete(self.authority.bindings, self.memberId)
		} else {
			self.authority.bindings[self.memberId] = &bridge.RecoveryBindingRow{KeySha256: keys.KeySha256(), Signer: self.selfId.Bytes(), At: self.n + 1}
		}
		self.authority.restored[self.memberId] = restored
	})
	return self.apply(edit)
}

// §22.5's §5 row: keychain.wrap is re-sealed at every change to the member's current binding as this device applies
// it, a RecoveryBind, a RecoveryRebind, a cascade's void and a restored binding signed again, with no HPKE copy while
// none is current or while the one in effect is a restored one.
func TestSealerFollowsTheCurrentBinding(t *testing.T) {
	world := newRevokeTestWorld(t)
	first, second := testRecoveryKeys(t, 0x10), testRecoveryKeys(t, 0x50)
	for _, keys := range []*RecoveryKeys{first, second} {
		if err := world.sidecar.keepRecoveryPublicKey(keys.KeySha256(), keys.XwingPublicKey()); err != nil {
			t.Fatal(err)
		}
	}
	if sealedTo := world.sealedTo(t); sealedTo != "" {
		t.Fatalf("a copy before any binding: %s", sealedTo)
	}
	world.bind(first, false, nil)
	if sealedTo := world.sealedTo(t); sealedTo != hex.EncodeToString(first.KeySha256()) {
		t.Fatalf("after the bind: %q", sealedTo)
	}
	if _, _, err := world.instance.openRecoveryRoots(world.sidecar.currentIdentity().NetworkId, first); err != nil {
		t.Fatal(err)
	}
	// a rebind: the old code gets no new wrap
	world.bind(second, false, nil)
	if sealedTo := world.sealedTo(t); sealedTo != hex.EncodeToString(second.KeySha256()) {
		t.Fatalf("after the rebind: %q", sealedTo)
	}
	if _, _, err := world.instance.openRecoveryRoots(world.sidecar.currentIdentity().NetworkId, first); !errors.Is(err, ErrRecoveryCopyKey) {
		t.Errorf("the old code after a rebind: %v", err)
	}
	// the cascade voids the rebind and restores the first binding, which takes no wrap until signed again
	world.bind(first, true, func(entry *SidecarAuthorityEntry) {
		entry.VoidedBindings = []SidecarVoidedBinding{{MemberId: world.memberId, KeySha256: second.KeySha256(), Signer: world.otherId.Bytes()}}
	})
	if sealedTo := world.sealedTo(t); sealedTo != "" {
		t.Fatalf("a copy under a restored binding: %q", sealedTo)
	}
	// a signer outside P signs the restored binding again
	world.bind(first, false, nil)
	if sealedTo := world.sealedTo(t); sealedTo != hex.EncodeToString(first.KeySha256()) {
		t.Fatalf("after the restored binding was signed again: %q", sealedTo)
	}
	// no binding at all
	world.bind(nil, false, nil)
	if sealedTo := world.sealedTo(t); sealedTo != "" {
		t.Fatalf("a copy with no binding: %q", sealedTo)
	}
	// an entry that changes no binding leaves keychain.wrap as it was
	wrapPath := keychainWrapPath(world.sidecar.currentIdentity().NetworkId)
	before := readBackend(t, world.instance.backend, wrapPath)
	world.apply(nil)
	if !bytes.Equal(before, readBackend(t, world.instance.backend, wrapPath)) {
		t.Error("keychain.wrap was rewritten by an entry that changed no binding")
	}
}

// A device that did not sign a binding learns its X-Wing key from the record's sealed body, checked against the
// record's own key hash and this network's genesis, and seals to it; a body sealed for another genesis is not learned.
func TestSealerLearnsABindingFromItsRecord(t *testing.T) {
	world := newRevokeTestWorld(t)
	genesisSha256 := sha256.Sum256([]byte("a synthetic Signed Genesis"))
	if err := world.sidecar.TrustFirstUse(genesisSha256[:]); err != nil {
		t.Fatal(err)
	}
	configKeys := &testConfigKeys{key: testConfigSealKey(3)}
	t.Cleanup(world.sidecar.InstallConfigKeys(configKeys))
	networkId := world.sidecar.currentIdentity().NetworkId
	record := func(keys *RecoveryKeys, signedGenesis []byte) []byte {
		genesisSig, err := keys.SignGenesis(networkId, signedGenesis)
		if err != nil {
			t.Fatal(err)
		}
		header := &bridge.StatementHeader{NetworkId: networkId.Bytes(), Nonce: countingBytes(0x44, configNonceByteCount)}
		sealedBody, err := SealConfigBody(configKeys.key, NewConfigSealContext(bridge.SignedType_SIGNED_RECOVERY_BIND, header), &protocol.RecoveryBindBody{
			XwingPublicKey: keys.XwingPublicKey(), Ed25519PublicKey: keys.Ed25519PublicKey(), GenesisSig: genesisSig,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		statementBytes, err := proto.Marshal(&protocol.RecoveryBind{
			Header: header, MemberId: world.memberId.Bytes(), Ed25519PublicKeySha256: keys.KeySha256(), SealedBody: sealedBody,
		})
		if err != nil {
			t.Fatal(err)
		}
		return statementBytes
	}
	forged := testRecoveryKeys(t, 0x50)
	otherGenesisSha256 := sha256.Sum256([]byte("another genesis"))
	world.bind(forged, false, func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{{Type: bridge.SignedType_SIGNED_RECOVERY_BIND, Body: record(forged, otherGenesisSha256[:])}}
	})
	if sealedTo := world.sealedTo(t); sealedTo != "" {
		t.Fatalf("sealed to a binding whose genesis_sig fails: %q", sealedTo)
	}
	keys := testRecoveryKeys(t, 0x10)
	world.bind(keys, false, func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{{Type: bridge.SignedType_SIGNED_RECOVERY_BIND, Body: record(keys, genesisSha256[:])}}
	})
	if sealedTo := world.sealedTo(t); sealedTo != hex.EncodeToString(keys.KeySha256()) {
		t.Fatalf("after another device's bind: %q", sealedTo)
	}
}

// The AuthPin at each seal and re-seal is recorded, and at a void recovery_rebind's Evidence names the span the copy
// was sealed to the voided binding: from the pin it was sealed at to the pin the void ended it at.
func TestVoidRecordsSealSpan(t *testing.T) {
	world := newRevokeTestWorld(t)
	keys := testRecoveryKeys(t, 0x10)
	if err := world.sidecar.keepRecoveryPublicKey(keys.KeySha256(), keys.XwingPublicKey()); err != nil {
		t.Fatal(err)
	}
	sealedAt := world.bind(keys, false, nil)
	world.apply(nil)
	voidedAt := world.bind(nil, false, func(entry *SidecarAuthorityEntry) {
		entry.VoidedBindings = []SidecarVoidedBinding{{MemberId: world.memberId, KeySha256: keys.KeySha256(), Signer: world.otherId.Bytes()}}
	})
	spans, err := world.sidecar.RecoverySealSpans(keys.KeySha256())
	if err != nil {
		t.Fatal(err)
	}
	wantSealed, _ := proto.Marshal(sealedAt.Pin)
	wantEnded, _ := proto.Marshal(voidedAt.Pin)
	if len(spans) != 1 || !bytes.Equal(spans[0][0], wantSealed) || !bytes.Equal(spans[0][1], wantEnded) {
		t.Fatalf("spans %x", spans)
	}
	rebinds := world.events.of(SidecarEventRecoveryRebind)
	if len(rebinds) != 1 || !bytes.Equal(rebinds[0].Evidence[0], wantSealed) || !bytes.Equal(rebinds[0].Evidence[1], wantEnded) {
		t.Fatalf("the void's alarm names no span: %+v", rebinds)
	}
	if sealedTo := world.sealedTo(t); sealedTo != "" {
		t.Errorf("a copy to a voided binding: %q", sealedTo)
	}
}

// A world whose device may sign its member's binding: an anchored genesis, a config key, and the gate on.
func newRecoveryBindWorld(t *testing.T) (*revokeTestWorld, *testConfigKeys, []byte) {
	t.Helper()
	world := newRevokeTestWorld(t)
	world.sidecar.settings.RecoveryBindings = true
	genesisSha256 := sha256.Sum256([]byte("a synthetic Signed Genesis"))
	if err := world.sidecar.TrustFirstUse(genesisSha256[:]); err != nil {
		t.Fatal(err)
	}
	configKeys := &testConfigKeys{key: testConfigSealKey(3)}
	t.Cleanup(world.sidecar.InstallConfigKeys(configKeys))
	return world, configKeys, genesisSha256[:]
}

// The keys a rotation's words derive.
func rotationKeys(t *testing.T, rotation *RecoveryRotation) *RecoveryKeys {
	t.Helper()
	code, err := ParseRecoveryCode(strings.Join(rotation.Words, " "))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := code.Keys()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// The gate, the mode and the signer: nothing is signed while SidecarSettings.RecoveryBindings is off, from MCP, a
// hook or an unconfirmed call, or on a device that is not its member's consented one.
func TestRotateRecoveryRefusals(t *testing.T) {
	world, _, _ := newRecoveryBindWorld(t)
	ctx := context.Background()
	world.sidecar.settings.RecoveryBindings = false
	if _, err := world.sidecar.RotateRecovery(ctx, false, SidecarActConfirmed, nil); !errors.Is(err, ErrRecoveryBindingGated) {
		t.Errorf("gated: %v", err)
	}
	world.sidecar.settings.RecoveryBindings = true
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := world.sidecar.RotateRecovery(ctx, false, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	world.authority.edit(func() { world.authority.consents[[2]Id{world.selfId, world.memberId}] = false })
	if _, err := world.sidecar.RotateRecovery(ctx, false, SidecarActConfirmed, nil); !errors.Is(err, ErrRecoveryBindingNotEligible) {
		t.Errorf("unconsented: %v", err)
	}
	world.authority.edit(func() { world.authority.consents[[2]Id{world.selfId, world.memberId}] = true })
	world.editRow(world.selfId, func(row *bridge.SidecarRow) {
		row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	})
	if _, err := world.sidecar.RotateRecovery(ctx, false, SidecarActConfirmed, nil); !errors.Is(err, ErrRecoveryBindingNotEligible) {
		t.Errorf("read_only: %v", err)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Errorf("%d statements posted by refused rotations", len(posts))
	}
	// a refused post binds nothing, and no code is shown
	world.editRow(world.selfId, func(row *bridge.SidecarRow) { row.Capabilities = 0 })
	world.deltaApi.answers = []string{"refused"}
	if rotation, err := world.sidecar.RotateRecovery(ctx, false, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarActRefused) || rotation != nil {
		t.Errorf("a refused post: %v, %+v", err, rotation)
	}
}

// A first rotation signs a RecoveryBind whose sealed body holds both public keys of the code it answers and a
// genesis_sig over this network's anchored genesis; a second signs a RecoveryRebind naming the first, routine or
// compromise; and once each is applied the copy is sealed to the new binding, so the old code gets no new wrap, while a
// backup taken before the rebind still opens under the old code (§5.9's backup rule).
func TestRotateRecoveryBindsThenRebinds(t *testing.T) {
	world, configKeys, genesisSha256 := newRecoveryBindWorld(t)
	ctx := context.Background()
	networkId := world.sidecar.currentIdentity().NetworkId

	first, err := world.sidecar.RotateRecovery(ctx, false, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Words) != recoveryCodeWordCount || first.Entry == nil || first.PreviousKeySha256 != nil || first.Pending {
		t.Fatalf("the first rotation: %+v", first)
	}
	firstKeys := rotationKeys(t, first)
	posts := world.posted(t)
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_RECOVERY_BIND {
		t.Fatalf("posted %d statements", len(posts))
	}
	bind := &protocol.RecoveryBind{}
	if err := proto.Unmarshal(posts[0].GetBody(), bind); err != nil {
		t.Fatal(err)
	}
	body := &protocol.RecoveryBindBody{}
	if _, err := OpenConfigBody(bind.GetSealedBody(), NewConfigSealContext(bridge.SignedType_SIGNED_RECOVERY_BIND, bind.GetHeader()), configKeys.ConfigKeyAt, body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bind.GetMemberId(), world.memberId.Bytes()) || len(bind.GetPrevSha256()) != 0 ||
		!bytes.Equal(bind.GetEd25519PublicKeySha256(), firstKeys.KeySha256()) || !bytes.Equal(first.KeySha256, firstKeys.KeySha256()) ||
		!bytes.Equal(body.GetEd25519PublicKey(), firstKeys.Ed25519PublicKey()) || !bytes.Equal(body.GetXwingPublicKey(), firstKeys.XwingPublicKey()) {
		t.Fatalf("the bind is not of the code shown")
	}
	if err := VerifyRecoveryGenesisSig(body.GetEd25519PublicKey(), networkId, genesisSha256, body.GetGenesisSig()); err != nil {
		t.Fatal(err)
	}
	// this device applies its own bind: the copy is sealed to it
	world.bind(firstKeys, false, nil)
	if sealedTo := world.sealedTo(t); sealedTo != hex.EncodeToString(firstKeys.KeySha256()) {
		t.Fatalf("after the bind: %q", sealedTo)
	}
	backup := backendSnapshot(t, world.instance.backend)

	second, err := world.sidecar.RotateRecovery(ctx, true, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondKeys := rotationKeys(t, second)
	posts = world.posted(t)
	rebind := &protocol.RecoveryRebind{}
	if len(posts) != 2 || bridge.SignedType(posts[1].GetType()) != bridge.SignedType_SIGNED_RECOVERY_REBIND || proto.Unmarshal(posts[1].GetBody(), rebind) != nil {
		t.Fatalf("posted %d statements", len(posts))
	}
	if !bytes.Equal(rebind.GetPrevSha256(), firstKeys.KeySha256()) || !bytes.Equal(second.PreviousKeySha256, firstKeys.KeySha256()) ||
		!bytes.Equal(rebind.GetEd25519PublicKeySha256(), secondKeys.KeySha256()) ||
		rebind.GetReason() != bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE || !second.Compromise {
		t.Fatalf("the rebind: %+v", rebind)
	}
	if len(second.Devices) != 2 || !second.Devices[0].This {
		t.Errorf("the rotation lists no devices to review: %+v", second.Devices)
	}
	world.bind(secondKeys, false, nil)
	if _, _, err := world.instance.openRecoveryRoots(networkId, secondKeys); err != nil {
		t.Fatal(err)
	}
	// afterwards the old code gets no new wrap and opens nothing here
	if _, _, err := world.instance.openRecoveryRoots(networkId, firstKeys); !errors.Is(err, ErrRecoveryCopyKey) {
		t.Errorf("the old code after the rebind: %v", err)
	}
	// the backup rule: a backup sealed before the rebind still opens under the old code, and not under the new
	restored := NewSidecarMemoryBackend()
	for path, content := range backup {
		putBackendFile(t, restored, path, content)
	}
	old := newInstanceOn(t, restored, newFakeKeyStore())
	if _, _, err := old.openRecoveryRoots(networkId, firstKeys); err != nil {
		t.Errorf("the backup under the old code: %v", err)
	}
	if _, _, err := old.openRecoveryRoots(networkId, secondKeys); !errors.Is(err, ErrRecoveryCopyKey) {
		t.Errorf("the backup under the new code: %v", err)
	}
}

// An AdminSet member's binding is an authority statement: where the log asks for more than one counted signer it
// goes as an AuthorityProposal carrying the sealed statement, and the result names the proposal.
func TestRotateRecoveryProposesForAnAdminSetMember(t *testing.T) {
	world, configKeys, _ := newRecoveryBindWorld(t)
	world.authority.edit(func() { world.authority.proposalTypes[bridge.SignedType_SIGNED_RECOVERY_BIND] = true })
	rotation, err := world.sidecar.RotateRecovery(context.Background(), false, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatal(err)
	}
	posts := world.posted(t)
	proposal := &protocol.AuthorityProposal{}
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL || proto.Unmarshal(posts[0].GetBody(), proposal) != nil {
		t.Fatalf("posted %d statements", len(posts))
	}
	wantId := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, posts[0].GetBody())
	if !bytes.Equal(rotation.ProposalId, wantId[:]) || rotation.Entry != nil {
		t.Errorf("the rotation names no proposal: %+v", rotation)
	}
	bind := &protocol.RecoveryBind{}
	if bridge.SignedType(proposal.GetStatementType()) != bridge.SignedType_SIGNED_RECOVERY_BIND || proto.Unmarshal(proposal.GetStatement(), bind) != nil {
		t.Fatal("the proposal carries no RecoveryBind")
	}
	body := &protocol.RecoveryBindBody{}
	if _, err := OpenConfigBody(bind.GetSealedBody(), NewConfigSealContext(bridge.SignedType_SIGNED_RECOVERY_BIND, bind.GetHeader()), configKeys.ConfigKeyAt, body); err != nil {
		t.Fatal(err)
	}
}

// No device keeps the code: after a rotation, neither the state directory's bytes nor any record of the core
// namespace as it decrypts holds the code's entropy, a seed, the Ed25519 private key or the words.
func TestCodeNeverPersisted(t *testing.T) {
	world, _, _ := newRecoveryBindWorld(t)
	rotation, err := world.sidecar.RotateRecovery(context.Background(), false, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatal(err)
	}
	code, err := ParseRecoveryCode(strings.Join(rotation.Words, " "))
	if err != nil {
		t.Fatal(err)
	}
	entropy := bytes.Clone(code.entropy[:])
	keys, err := deriveRecoveryKeys(entropy)
	if err != nil {
		t.Fatal(err)
	}
	world.bind(keys, false, nil)
	needles := map[string][]byte{
		"the entropy":             entropy,
		"the Ed25519 seed":        keys.ed25519Key.Seed(),
		"the words":               []byte(strings.Join(rotation.Words, " ")),
		"the first words":         []byte(strings.Join(rotation.Words[:4], " ")),
		"the entropy in hex":      []byte(hex.EncodeToString(entropy)),
		"the Ed25519 seed in hex": []byte(hex.EncodeToString(keys.ed25519Key.Seed())),
	}
	scan := func(where string, content []byte) {
		for name, needle := range needles {
			if bytes.Contains(content, needle) {
				t.Errorf("%s holds %s", where, name)
			}
		}
	}
	for path, content := range backendSnapshot(t, world.instance.backend) {
		scan(path, content)
	}
	secrets := world.sidecar.currentCoreSecrets()
	names, err := secrets.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("the core namespace lists nothing")
	}
	for _, name := range names {
		content, err := secrets.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		scan("the core record "+name, content)
	}
	// the sealer did keep what it may: the binding's public key, by its hash
	record, err := world.sidecar.loadRecoverySealRecord()
	if err != nil || !bytes.Equal(record.PublicKeys[hex.EncodeToString(keys.KeySha256())], keys.XwingPublicKey()) {
		t.Errorf("the sealer holds no public key of the binding: %v", err)
	}
}

// A host apart from the Sidecar hands over only a binding's public half: BindRecovery signs it once its genesis_sig
// verifies for this network's anchored genesis, and refuses one signed for another network or genesis, nothing signed.
func TestBindRecoveryChecksTheGenesisSig(t *testing.T) {
	world, _, genesisSha256 := newRecoveryBindWorld(t)
	ctx := context.Background()
	networkId, anchored, err := world.sidecar.RecoveryAnchor()
	if err != nil || !bytes.Equal(anchored, genesisSha256) || networkId != world.sidecar.currentIdentity().NetworkId {
		t.Fatalf("the anchor: %v", err)
	}
	keys := testRecoveryKeys(t, 0x10)
	otherGenesisSha256 := sha256.Sum256([]byte("another genesis"))
	wrongSig, err := keys.SignGenesis(networkId, otherGenesisSha256[:])
	if err != nil {
		t.Fatal(err)
	}
	binding := &RecoveryBinding{Ed25519PublicKey: keys.Ed25519PublicKey(), XwingPublicKey: keys.XwingPublicKey(), GenesisSig: wrongSig}
	if _, err := world.sidecar.BindRecovery(ctx, binding, false, SidecarActConfirmed, nil); !errors.Is(err, ErrRecoveryGenesisSig) {
		t.Errorf("another genesis: %v", err)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted", len(posts))
	}
	binding.GenesisSig, err = keys.SignGenesis(networkId, genesisSha256)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := world.sidecar.BindRecovery(ctx, binding, false, SidecarActConfirmed, nil)
	if err != nil || rotation.Words != nil || !bytes.Equal(rotation.KeySha256, keys.KeySha256()) || rotation.Entry == nil {
		t.Fatalf("the binding: %+v, %v", rotation, err)
	}
	// a lost answer leaves the statement pending, the result still naming the binding
	world.bind(keys, false, nil)
	world.deltaApi.answers = []string{"lost"}
	next := testRecoveryKeys(t, 0x50)
	nextSig, _ := next.SignGenesis(networkId, genesisSha256)
	rotation, err = world.sidecar.BindRecovery(ctx, &RecoveryBinding{Ed25519PublicKey: next.Ed25519PublicKey(), XwingPublicKey: next.XwingPublicKey(), GenesisSig: nextSig}, false, SidecarActConfirmed, nil)
	if !errors.Is(err, ErrSidecarActPending) || rotation == nil || !rotation.Pending || !bytes.Equal(rotation.PreviousKeySha256, keys.KeySha256()) {
		t.Fatalf("a lost answer: %+v, %v", rotation, err)
	}
}
