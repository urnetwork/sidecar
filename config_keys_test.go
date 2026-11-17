// §7.9's KeyRegister and KeyRevoke on the test network, both §16.6 profiles: a presence key registers by its member's
// consented, approval-capable device with its own proof over the body before field 9, an sshsig key with none, and each
// refused shape; LiveKeys lists what is not revoked, void or past its not_after. The registrations here are the fixture
// keys the presence tests countersign with. The KeyRegister rule reads no attestation (QD-924): a key registers alike
// whether its attestation chains to the test's roots or fails against them, readers of one log under swapped roots hold
// one state, and only their labels differ, presence (attestation refused) for the statement their roots refuse.

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
	return self.presenceRegisterBodyCarrying(member, key, prover, notAfter, nil)
}

// presenceRegisterBody with attestation as KeyRegister.attestation, field 6, which the proof covers with the rest of
// fields 1 to 8.
func (self *testConfigNet) presenceRegisterBodyCarrying(
	member Id,
	key *testPresenceKey,
	prover *testPresenceKey,
	notAfter int64,
	attestation []byte,
) []byte {
	register := &protocol.KeyRegister{
		Header:      self.header(),
		MemberId:    member.Bytes(),
		KeyId:       bytes.Clone(key.keyId),
		Alg:         key.alg,
		PublicKey:   bytes.Clone(key.publicKey),
		Attestation: bytes.Clone(attestation),
		Purpose:     bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		NotAfter:    notAfter,
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
	return self.registerPresenceKeyCarrying(device, key, nil)
}

// registerPresenceKey with attestation as its KeyRegister.attestation.
func (self *testConfigNet) registerPresenceKeyCarrying(device testConfigDevice, key *testPresenceKey, attestation []byte) ConfigVerdict {
	self.t.Helper()
	body := self.presenceRegisterBodyCarrying(device.memberId, key, key, self.timeMs+30*24*testConfigHourMs, attestation)
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

// A logged key's KeyRegister as the entry at its row's position carries it, and that entry's time: what a reader labels
// the key from (§16.6's labels row), where the reader retains the entry.
func testConfigLoggedKeyRegister(t testing.TB, reader *ConfigLog, keyId []byte) (*protocol.KeyRegister, int64) {
	t.Helper()
	row := reader.State().RegisteredKey(keyId)
	if row == nil {
		t.Fatalf("no key %x", keyId)
	}
	kept := reader.keptEntry(row.GetAt())
	if kept == nil {
		t.Fatalf("the entry at %d is not retained", row.GetAt())
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(kept.entry.GetBody(), signed); err != nil {
		t.Fatal(err)
	}
	register := &protocol.KeyRegister{}
	if err := proto.Unmarshal(signed.GetBody(), register); err != nil {
		t.Fatal(err)
	}
	return register, kept.entry.GetTimeMs()
}

// A KeyRegister takes effect whatever its attestation (QD-924; owner decision 327). One key registers on two runs of
// one network, with apple's own statement, which chains to the apple root the test pins, and with a forged one whose
// chain runs to a software key's CA, which fails against it; both runs take it under the test's pools and stand on the
// same rows but the replay ring, whose ids are the statements' own bytes: the same key row, the same one live key, and
// a covered statement of the device's refused alike without that key's countersignature. Nothing reads a pool, the
// net's reader and every other kind of reader included.
func TestAKeyRegisterTakesEffectWhateverItsAttestation(t *testing.T) {
	cas := newTestAttestCas(t)
	key := newTestPresenceKey(t, "webauthn-es256 key with an apple statement", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	forged := newTestAttestation(cas, key)
	forged.issuer = cas.software
	attestations := [][]byte{newTestAttestation(cas, key).attestation(t, "apple"), forged.attestation(t, "apple")}
	// under the test's pools the first chains and the second fails, so a rule that read them would split the runs
	for i, want := range []PresenceLabel{PresenceLabelAttested, 0} {
		label, err := verifyPresenceAttestation(attestations[i], key.publicKey, cas.roots(), testAttestSettings(), testAttestAt)
		if label != want || (want == 0) != errors.Is(err, ErrPresenceAttestation) {
			t.Fatalf("attestation %d under the test's pools: %s, %v", i, label, err)
		}
	}

	reads := testAttestRootsAsRelease(t, cas.roots())
	states := []*ConfigState{}
	for i, attestation := range attestations {
		net := newTestConfigNet(t)
		_, laptop := net.consentedMember("m")
		net.registerPresenceKeyCarrying(laptop, key, attestation)
		live := net.log.State().LiveKeys(laptop.sidecarId)
		if len(live) != 1 || !bytes.Equal(live[0].GetKeyId(), key.keyId) {
			t.Errorf("run %d: %d live keys", i, len(live))
		}
		// the laptop's next presence registration is covered by the key, whichever statement it carried
		other := newTestPresenceKey(t, "another webauthn-es256 key", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
		uncountersigned := net.signRaw(laptop, bridge.SignedType_SIGNED_KEY_REGISTER,
			net.presenceRegisterBody(laptop.memberId, other, other, net.timeMs+30*24*testConfigHourMs))
		if verdict := net.log.Check(uncountersigned, net.timeMs+1000); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigPresence) {
			t.Errorf("run %d: a covered statement without the key's countersignature: %v", i, verdict.Refusal)
		}
		net.everyReaderAgrees()
		states = append(states, net.log.State())
	}
	if n := reads.Load(); n != 0 {
		t.Errorf("the log read the release's pools %d times", n)
	}
	rowsBesideTheRing := func(state *ConfigState) []byte {
		rows := state.Rows()
		rows.Ring = nil
		return testConfigMarshal(t, rows)
	}
	if !bytes.Equal(rowsBesideTheRing(states[0]), rowsBesideTheRing(states[1])) {
		t.Errorf("the runs' rows differ:\n%v\n%v", states[0].Rows(), states[1].Rows())
	}
	if row := states[0].RegisteredKey(key.keyId); row == nil || !proto.Equal(row, states[1].RegisteredKey(key.keyId)) {
		t.Errorf("the key's rows %v and %v", row, states[1].RegisteredKey(key.keyId))
	}
}

// Readers of one log under swapped pools hold one state (QD-924; owner decision 327). A device registers two
// webauthn-es256 keys, one with apple's own statement and one with a forged one whose chain runs to a software key's
// CA, and readers apply the log under three releases' pools: the test's, which pin apple's root and refuse the forged
// statement; a release's that pin the forging CA as apple's root in its place, which refuse apple's own; and this
// build's, which pin none. None reads a pool while it applies the log, the net's own reader included, and each reaches
// the net's verdicts and state, both keys live in it. From the logged KeyRegister at its entry's time each labels the
// key whose statement its pools refuse presence (attestation refused), never asserted, and the other attested; this
// build's labels both asserted.
func TestReadersUnderSwappedRootsHoldOneState(t *testing.T) {
	cas := newTestAttestCas(t)
	release := presenceReleaseAttestationRoots()
	net := newTestConfigNet(t)
	_, laptop := net.consentedMember("m")
	genuine := newTestPresenceKey(t, "webauthn-es256 key with apple's statement", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	forged := newTestPresenceKey(t, "webauthn-es256 key with a forged apple statement", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	forgedAttestation := newTestAttestation(cas, forged)
	forgedAttestation.issuer = cas.software

	netReads := testAttestRootsAsRelease(t, cas.roots())
	net.registerPresenceKeyCarrying(laptop, genuine, newTestAttestation(cas, genuine).attestation(t, "apple"))
	net.registerPresenceKeyCarrying(laptop, forged, forgedAttestation.attestation(t, "apple"))
	if n := netReads.Load(); n != 0 {
		t.Errorf("the net's reader read the release's pools %d times", n)
	}
	if live := net.log.State().LiveKeys(laptop.sidecarId); len(live) != 2 {
		t.Fatalf("%d live keys", len(live))
	}

	from := net.log.State().Base().GetVersion() + 1
	for _, reader := range []struct {
		name    string
		roots   *presenceAttestationRoots
		genuine PresenceLabel
		forged  PresenceLabel
	}{
		{name: "the test's pools", roots: cas.roots(), genuine: PresenceLabelAttested, forged: PresenceLabelRefused},
		{name: "pools pinning the forging CA as apple's root", roots: cas.rootsPinningAsApple(cas.software),
			genuine: PresenceLabelRefused, forged: PresenceLabelAttested},
		{name: "this build's pools", roots: release, genuine: PresenceLabelAsserted, forged: PresenceLabelAsserted},
	} {
		reads := testAttestRootsAsRelease(t, reader.roots)
		log := net.newReader()
		if n := reads.Load(); n != 0 {
			t.Errorf("%s: the log read the release's pools %d times", reader.name, n)
		}
		for n := from; n <= net.n; n += 1 {
			want, got := net.log.keptEntry(n), log.keptEntry(n)
			if want == nil || got == nil || want.verdict.Accepted() != got.verdict.Accepted() {
				t.Errorf("%s: another verdict at %d", reader.name, n)
			}
		}
		testConfigStatesEqual(t, log.State(), net.log.State())
		for _, labelled := range []struct {
			key  *testPresenceKey
			want PresenceLabel
		}{{key: genuine, want: reader.genuine}, {key: forged, want: reader.forged}} {
			register, atMillis := testConfigLoggedKeyRegister(t, log, labelled.key.keyId)
			if label := PresenceKeyLabel(register, atMillis); label != labelled.want {
				t.Errorf("%s labels the %s %s; want %s", reader.name, labelled.key.seed, label, labelled.want)
			}
		}
		// the labels read the pools the log never did
		if n := reads.Load(); n != 2 {
			t.Errorf("%s: %d reads of the pools for two labels", reader.name, n)
		}
	}
	net.everyReaderAgrees()
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
