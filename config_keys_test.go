// §7.9's KeyRegister and KeyRevoke on the test network, both §16.6 profiles: a presence key registers by its member's
// consented, approval-capable device with its own proof over the body before field 9, an sshsig key with none, and each
// refused shape; LiveKeys lists what is not revoked, void or past its not_after. The registrations here are the fixture
// keys the presence tests countersign with.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// raw body bytes signed by signer's identity key under the type's purpose, as a Signed's bytes.
func (self *testConfigNet) signRaw(signer testConfigDevice, signedType bridge.SignedType, bodyBytes []byte) []byte {
	purpose, _ := ConfigStatementPurpose(signedType)
	return testConfigMarshal(self.t, &bridge.Signed{
		Body:      bodyBytes,
		SignerId:  signer.sidecarId.Bytes(),
		Signature: ed25519.Sign(signer.key, bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	})
}

// A KeyRegister body at the tip registering a presence key for member: fields 1 to 8 deterministically encoded, then
// the proof the prover key makes over them (QD-086), which is the key itself unless a test spoils it.
func (self *testConfigNet) presenceRegisterBody(member Id, key *testPresenceKey, prover *testPresenceKey, notAfter int64) []byte {
	register := &protocol.KeyRegister{
		Header:    self.header(),
		MemberId:  member.Bytes(),
		KeyId:     bytes.Clone(key.keyId),
		Alg:       key.alg,
		PublicKey: bytes.Clone(key.publicKey),
		Purpose:   bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		NotAfter:  notAfter,
	}
	prefix := testConfigMarshal(self.t, register)
	proof := prover.sign(self.t, testGoodPresenceAssertion(), PresenceKeyProofPurpose, bridge.SignedType_SIGNED_KEY_REGISTER, prefix)
	body := protowire.AppendTag(bytes.Clone(prefix), 9, protowire.BytesType)
	body = protowire.AppendBytes(body, proof.GetSignature())
	if proof.GetWebauthn() != nil {
		body = protowire.AppendTag(body, 10, protowire.BytesType)
		body = protowire.AppendBytes(body, testConfigMarshal(self.t, proof.GetWebauthn()))
	}
	return body
}

// Registers a presence key for device's member, signed by device and, once the device holds a key, countersigned by
// the one it registered last, since a presence key's KeyRegister is covered; fails the test unless it takes effect.
func (self *testConfigNet) registerPresenceKey(device testConfigDevice, key *testPresenceKey) ConfigVerdict {
	self.t.Helper()
	body := self.presenceRegisterBody(device.memberId, key, key, self.timeMs+30*24*testConfigHourMs)
	signedBytes := self.signRaw(device, bridge.SignedType_SIGNED_KEY_REGISTER, body)
	if previous := self.presenceKeys[device.sidecarId]; previous != nil {
		statements := []*testPresenceActStatement{testConfigActStatement(self.t, signedBytes)}
		previous.countersign(self.t, testGoodPresenceAssertion(), device.sidecarId.Bytes(), statements)
		signedBytes = testConfigMarshal(self.t, statements[0].signed)
	}
	verdict := self.push(self.makeEntry(bridge.AuthEntryKindStatement, signedBytes))
	if !verdict.Accepted() {
		self.t.Fatalf("the KeyRegister: %v", verdict.Refusal)
	}
	if self.presenceKeys == nil {
		self.presenceKeys = map[Id]*testPresenceKey{}
	}
	self.presenceKeys[device.sidecarId] = key
	return verdict
}

// Both profiles' keys register with their proofs, each row keeping its signer and position; LiveKeys lists them.
func TestAPresenceKeyRegistersWithItsOwnProof(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop := net.consentedMember("m")
	for _, key := range testPresenceKeys(t) {
		verdict := net.registerPresenceKey(laptop, key)
		row := net.log.State().RegisteredKey(key.keyId)
		if row == nil || row.GetAt() != verdict.Pin.GetVersion() || !bytes.Equal(row.GetSigner(), laptop.sidecarId.Bytes()) ||
			row.GetAlg() != key.alg || !bytes.Equal(row.GetPublicKey(), key.publicKey) {
			t.Errorf("%s: the row %v", key.alg, row)
		}
	}
	if live := net.log.State().LiveKeys(laptop.sidecarId); len(live) != 2 {
		t.Errorf("%d live keys", len(live))
	}
	if live := net.log.State().LiveKeys(net.owner.sidecarId); len(live) != 0 {
		t.Errorf("the owner's device holds %d live keys", len(live))
	}
	net.everyReaderAgrees()
}

// What a KeyRegister is refused for: a proof by another key, a proof missing, an sshsig key carrying one, a malformed
// point, a key_id registered before, a past not_after, and a signer that is no consented, approval-capable device of
// the member, a read_only one included.
func TestAKeyRegistersOnlyWithItsShapeAndSigner(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	readOnly := net.device("m read only", member)
	net.admitDevice(laptop, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	unconsented := net.device("m unconsented", member)
	net.admitDevice(net.owner, unconsented, 0)
	key := newTestPresenceKey(t, "registered key", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	other := newTestPresenceKey(t, "another key", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	notAfter := net.timeMs + 30*24*testConfigHourMs
	post := func(signer testConfigDevice, body []byte) ConfigVerdict {
		return net.push(net.makeEntry(bridge.AuthEntryKindStatement, net.signRaw(signer, bridge.SignedType_SIGNED_KEY_REGISTER, body)))
	}
	refuse := func(name string, signer testConfigDevice, body []byte, want error) {
		t.Helper()
		if verdict := post(signer, body); verdict.Accepted() || !errors.Is(verdict.Refusal, want) {
			t.Errorf("%s: %v, want %v", name, verdict.Refusal, want)
		}
	}
	refuse("another key's proof", laptop, net.presenceRegisterBody(member, key, other, notAfter), ErrConfigRule)
	noProof := testConfigMarshal(t, &protocol.KeyRegister{Header: net.header(), MemberId: member.Bytes(), KeyId: key.keyId, Alg: key.alg,
		PublicKey: key.publicKey, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, NotAfter: notAfter})
	refuse("no proof", laptop, noProof, ErrConfigRule)
	badPoint := testConfigMarshal(t, &protocol.KeyRegister{Header: net.header(), MemberId: member.Bytes(), KeyId: key.keyId, Alg: key.alg,
		PublicKey: bytes.Repeat([]byte{0x04}, 65), Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, NotAfter: notAfter})
	refuse("a malformed point", laptop, badPoint, ErrConfigRule)
	refuse("a past not_after", laptop, net.presenceRegisterBody(member, key, key, net.timeMs), ErrConfigRule)
	refuse("a read_only device", readOnly, net.presenceRegisterBody(member, key, key, notAfter), ErrConfigReadOnly)
	refuse("an unconsented device", unconsented, net.presenceRegisterBody(member, key, key, notAfter), ErrConfigAuthority)
	refuse("another member's device", net.owner, net.presenceRegisterBody(member, key, key, notAfter), ErrConfigAuthority)

	sshKey := testConfigDeviceKey("m ssh key").Public().(ed25519.PublicKey)
	sshRegister := &protocol.KeyRegister{Header: net.header(), MemberId: member.Bytes(), KeyId: []byte("ssh key"), Alg: bridge.KeyAlg_KEY_ALG_SSH_ED25519,
		PublicKey: sshKey, Purpose: bridge.KeyPurpose_KEY_PURPOSE_SSHSIG, NotAfter: notAfter, KeySignature: []byte("a proof no sshsig key carries")}
	refuse("an sshsig key with a proof", laptop, testConfigMarshal(t, sshRegister), ErrConfigRule)
	sshRegister.KeySignature = nil
	sshRegister.Header = net.header()
	if verdict := post(laptop, testConfigMarshal(t, sshRegister)); !verdict.Accepted() {
		t.Fatalf("an sshsig key: %v", verdict.Refusal)
	}
	tablet := net.device("m tablet", member)
	net.admitDevice(laptop, tablet, 0)
	net.registerPresenceKey(laptop, key)
	// the laptop's own next presence registration is covered now, so a second device of the member tries the key_id
	refuse("a key_id registered before", tablet, net.presenceRegisterBody(member, key, key, notAfter), ErrConfigRule)
	refuse("a covered registration without a countersignature", laptop, net.presenceRegisterBody(member, other, other, notAfter), ErrConfigPresence)
	if live := net.log.State().LiveKeys(laptop.sidecarId); len(live) != 1 {
		t.Errorf("an sshsig key is live as a presence key: %d", len(live))
	}
	net.everyReaderAgrees()
}

// A key's KeyRevoke by its member's consented, approval-capable device revokes it once; LiveKeys drops it, and a key
// past its not_after; a revocation of no key is refused.
func TestAKeyRevokeEndsItsLife(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	_ = member
	keys := testPresenceKeys(t)
	for _, key := range keys {
		net.registerPresenceKey(laptop, key)
	}
	revokeBytes := func(keyId []byte) []byte {
		return net.sign(laptop, bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{Header: net.header(), KeyId: keyId})
	}
	// a presence key's KeyRevoke is covered, so with two live keys it carries a countersignature by one
	statements := []*testPresenceActStatement{testConfigActStatement(t, revokeBytes(keys[0].keyId))}
	keys[1].countersign(t, testGoodPresenceAssertion(), laptop.sidecarId.Bytes(), statements)
	revoked := net.push(net.makeEntry(bridge.AuthEntryKindStatement, testConfigMarshal(t, statements[0].signed)))
	if !revoked.Accepted() {
		t.Fatalf("the KeyRevoke: %v", revoked.Refusal)
	}
	state := net.log.State()
	if state.RegisteredKey(keys[0].keyId).GetRevokedAt() != revoked.Pin.GetVersion() || len(state.LiveKeys(laptop.sidecarId)) != 1 {
		t.Errorf("the revoked key: %v", state.RegisteredKey(keys[0].keyId))
	}
	if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, revokeBytes([]byte("no such key")))); verdict.Accepted() {
		t.Error("a revocation of no key")
	}
	net.wait(31 * 24 * testConfigHourMs)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("a later entry"))
	if live := net.log.State().LiveKeys(laptop.sidecarId); len(live) != 0 {
		t.Errorf("%d keys live past their not_after", len(live))
	}
}

// A Signed's bytes as one statement of an act, its purpose by its type.
func testConfigActStatement(t testing.TB, signedBytes []byte) *testPresenceActStatement {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		t.Fatal(err)
	}
	purpose, _ := ConfigStatementPurpose(bridge.SignedType(signed.GetType()))
	return &testPresenceActStatement{purpose: purpose, signed: signed}
}
