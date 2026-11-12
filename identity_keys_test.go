package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An open instance holding a keychain for network networkId, and the core's namespace of it.
func newIdentityTestSecrets(t *testing.T, networkId Id) (*SidecarInstance, SidecarSecrets) {
	t.Helper()
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := instance.createKeychain(networkId); err != nil {
		t.Fatal(err)
	}
	return instance, instance.secrets(networkId, sidecarCoreSecretsNamespace)
}

// A Sidecar at Unenrolled holding a persisted identity of fresh keys, with the instance behind it and the keys.
func newIdentityTestSidecar(t *testing.T) (*Sidecar, *SidecarInstance, *sidecarIdentityKeys) {
	t.Helper()
	binding := testBindingFields()
	instance, secrets := newIdentityTestSecrets(t, binding.NetworkId)
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedBinding, err := NewSidecarIdentityBinding(binding, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); err != nil {
		t.Fatal(err)
	}
	sidecar := newSidecarBase(nil, cheapKeychainSettings())
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled}) {
		t.Fatal("no move to unenrolled")
	}
	if err := sidecar.adoptIdentity(secrets); err != nil {
		t.Fatal(err)
	}
	return sidecar, instance, keys
}

// The identity record goes into the keychain whole and comes back the same, public keys from the seeds.
func TestIdentityRecordRoundTrip(t *testing.T) {
	sidecar, _, keys := newIdentityTestSidecar(t)
	identity := sidecar.currentIdentity()
	if identity == nil {
		t.Fatal("no identity adopted")
	}
	want := testBindingFields()
	if identity.NetworkId != want.NetworkId || identity.SidecarId != want.SidecarId || identity.ClientId != want.ClientId ||
		identity.Generation != 1 || !bytes.Equal(identity.IdentityPublicKey, keys.identityPublicKey()) ||
		!bytes.Equal(identity.ClientPublicKey, keys.clientPublicKey()) {
		t.Fatalf("identity differs: %+v", identity)
	}
	record, err := loadSidecarIdentity(sidecar.coreSecrets)
	if err != nil {
		t.Fatal(err)
	}
	defer record.keys.erase()
	if !bytes.Equal(record.keys.identitySeed, keys.identitySeed) || !bytes.Equal(record.keys.clientKeySeed, keys.clientKeySeed) {
		t.Fatal("seeds differ")
	}
	if _, err := VerifySidecarIdentityBinding(record.binding); err != nil {
		t.Fatalf("the kept binding: %v", err)
	}
}

// Enrollment persists nothing that does not match: a binding of other keys is refused, and nothing is written.
func TestPersistRefusesABindingOfOtherKeys(t *testing.T) {
	binding := testBindingFields()
	_, secrets := newIdentityTestSecrets(t, binding.NetworkId)
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identitySeed, clientKeySeed := testBindingSeeds()
	signedBinding, err := NewSidecarIdentityBinding(binding, identitySeed, clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); !errors.Is(err, ErrSidecarBindingInvalid) {
		t.Fatalf("%v", err)
	}
	if _, err := loadSidecarIdentity(secrets); !errors.Is(err, ErrSidecarNoIdentity) {
		t.Fatalf("something was written: %v", err)
	}
}

// D-CORE-15: a record that does not decode is a failure, never absence, so nothing reads it as a first run.
func TestCorruptIdentityRecordIsFailed(t *testing.T) {
	binding := testBindingFields()
	_, secrets := newIdentityTestSecrets(t, binding.NetworkId)
	for _, corrupt := range [][]byte{{}, []byte("URID"), bytes.Repeat([]byte{0xff}, 200)} {
		if err := secrets.Put(sidecarIdentityRecordName, corrupt); err != nil {
			t.Fatal(err)
		}
		_, err := loadSidecarIdentity(secrets)
		if !errors.Is(err, ErrSidecarStoreFailed) || errors.Is(err, ErrSidecarNoIdentity) {
			t.Errorf("%v", err)
		}
	}
	// a good record cut short, and one with a byte past its end
	keys, _ := newSidecarIdentityKeys(rand.Reader)
	signedBinding, err := NewSidecarIdentityBinding(binding, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); err != nil {
		t.Fatal(err)
	}
	encoded, err := secrets.Get(sidecarIdentityRecordName)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range [][]byte{encoded[:len(encoded)-1], append(bytes.Clone(encoded), 0)} {
		if _, err := decodeSidecarIdentityRecord(corrupt); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%v", err)
		}
	}
}

// Generation n+1 keeps the identity key and draws a new ClientKey (§5.5).
func TestNewClientKeyKeepsTheIdentityKey(t *testing.T) {
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	next, err := keys.withNewClientKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(next.identityPublicKey(), keys.identityPublicKey()) || bytes.Equal(next.clientPublicKey(), keys.clientPublicKey()) {
		t.Fatal("the new generation's keys are wrong")
	}
	if bytes.Equal(keys.identitySeed, keys.clientKeySeed) {
		t.Fatal("the identity key and ClientKey are one seed")
	}
	next.erase()
	if !bytes.Equal(next.identitySeed, make([]byte, ed25519.SeedSize)) || !bytes.Equal(keys.identitySeed, keys.identitySeed) {
		t.Fatal("erase")
	}
	if bytes.Equal(keys.identitySeed, make([]byte, ed25519.SeedSize)) {
		t.Fatal("erasing the next generation zeroed this one's identity seed")
	}
}

// A failed draw makes no key.
func TestNoRandomnessNoKey(t *testing.T) {
	if _, err := newSidecarIdentityKeys(bytes.NewReader(make([]byte, 40))); err == nil {
		t.Fatal("keys from a short draw")
	}
}

// Sign builds §6.9's Signed under the identity key, with signer_id the sidecar_id, which VerifySigned accepts.
func TestSignBuildsAStatementOfTheIdentityKey(t *testing.T) {
	sidecar, _, keys := newIdentityTestSidecar(t)
	body := []byte("synthetic statement body")
	agentId := NewId()
	signed, err := sidecar.Sign(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE, body, &agentId)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		bridge.SignedKeyAlgEd25519, keys.identityPublicKey()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed.SignerId, testBindingFields().SidecarId.Bytes()) || len(signed.KeyId) != 0 {
		t.Fatal("signer_id is not the sidecar_id")
	}
	body[0] = 'X'
	if signed.Body[0] == 'X' {
		t.Fatal("the Signed shares the caller's body")
	}
}

// Sign refuses, before reading a key, a type the identity key never signs and a purpose that is not its type's.
func TestSignRefusesUnknownType(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	cases := []struct {
		purpose    string
		signedType bridge.SignedType
	}{
		{purpose: bridge.SignedPurposeAuthority, signedType: bridge.SignedType_SIGNED_TYPE_NONE},
		{purpose: bridge.SignedPurposeAuthority, signedType: bridge.SignedType(0x7777)},
		{purpose: "socket-ticket", signedType: bridge.SignedType_SIGNED_SOCKET_TICKET},
		{purpose: "window-delegation", signedType: bridge.SignedType_SIGNED_SHARE_CERT},
		{purpose: sidecarBindingIdentityPurpose, signedType: bridge.SignedType_SIGNED_SIDECAR_BINDING},
		{purpose: sidecarBindingClientPurpose, signedType: bridge.SignedType_SIGNED_SIDECAR_BINDING},
		{purpose: bridge.SignedPurposeAcl, signedType: bridge.SignedType_SIGNED_SIDECAR_REVOKE},
		{purpose: "", signedType: bridge.SignedType_SIGNED_EVS_PUSH},
		{purpose: "presence-act", signedType: bridge.SignedType_SIGNED_APPROVAL_DECISION},
	}
	for _, c := range cases {
		signed, err := sidecar.Sign(c.purpose, c.signedType, []byte("synthetic"), nil)
		if !errors.Is(err, ErrSidecarSignRefused) || signed != nil {
			t.Errorf("%q %#x: %v", c.purpose, int32(c.signedType), err)
		}
	}
}

// Every type signed.proto registers is in Sign's table or refused on purpose, so a type an area adds without a
// purpose here fails this test rather than becoming signable by accident.
func TestEverySignedTypeHasAnIdentityPurposeOrIsRefused(t *testing.T) {
	refused := map[bridge.SignedType]bool{
		bridge.SignedType_SIGNED_TYPE_NONE:       true,
		bridge.SignedType_SIGNED_SOCKET_TICKET:   true,
		bridge.SignedType_SIGNED_SHARE_CERT:      true,
		bridge.SignedType_SIGNED_SIDECAR_BINDING: true,
		// the identity key signs it only through AgentSubkey, never for Sign's callers (identity_agent.go)
		bridge.SignedType_SIGNED_AGENT_CERT: true,
	}
	for number := range bridge.SignedType_name {
		signedType := bridge.SignedType(number)
		_, ok := sidecarIdentitySignedPurpose(signedType)
		if ok == refused[signedType] {
			t.Errorf("%s: in the table %v, refused %v", signedType, ok, refused[signedType])
		}
	}
}

// D-CORE-6: the ClientKey never signs a statement. No statement Sign makes verifies under it, and no purpose of
// the binding is signable through Sign.
func TestClientKeyNeverSignsStatements(t *testing.T) {
	sidecar, _, keys := newIdentityTestSidecar(t)
	for number := range bridge.SignedType_name {
		signedType := bridge.SignedType(number)
		purpose, ok := sidecarIdentitySignedPurpose(signedType)
		if !ok {
			continue
		}
		signed, err := sidecar.Sign(purpose, signedType, []byte("synthetic"), nil)
		if err != nil {
			t.Fatalf("%s: %v", signedType, err)
		}
		signedBytes := bridge.SignedBytes(purpose, signedType, signed.Body)
		if ed25519.Verify(keys.clientPublicKey(), signedBytes, signed.Signature) {
			t.Fatalf("%s verifies under the ClientKey", signedType)
		}
		if !ed25519.Verify(keys.identityPublicKey(), signedBytes, signed.Signature) {
			t.Fatalf("%s does not verify under the identity key", signedType)
		}
	}
}

// Sign answers a clean error while Locked, whether the sidecar or only its keychain is, and before enrollment.
func TestSignWhileLockedIsAnError(t *testing.T) {
	sidecar, instance, _ := newIdentityTestSidecar(t)
	instance.Lock()
	_, err := sidecar.Sign(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE, []byte("synthetic"), nil)
	if !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("a locked keychain: %v", err)
	}
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateLocked}) {
		t.Fatal("no move to locked")
	}
	_, err = sidecar.Sign(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE, []byte("synthetic"), nil)
	if !errors.Is(err, ErrSidecarStoreLocked) || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("a locked sidecar: %v", err)
	}

	unenrolled := newSidecarBase(nil, cheapKeychainSettings())
	unenrolled.applyTransition(sidecarTransition{to: SidecarStateUnenrolled})
	_, err = unenrolled.Sign(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE, []byte("synthetic"), nil)
	if !errors.Is(err, ErrSidecarNoIdentity) {
		t.Fatalf("before enrollment: %v", err)
	}
}
