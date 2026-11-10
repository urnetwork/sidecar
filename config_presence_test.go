// §7.9's presence row on the test network, FS-124's M2 cases at a long-running reader, a new device and a rows-only
// gate alike (api's verifier is the rows-only one): a covered statement by a signer with a live presence key is refused
// with no countersignature, another key's, another device's key's, a revoked or expired key's, another act's root,
// another signer's act or a path that misses, and lands with a valid one; a five-statement act verifies in any order or
// alone; an uncovered statement needs none and a countersignature the row does not require is ignored; and a thief
// holding a device's identity key but not its presence key gets nothing covered past every reader, though a malicious
// sequencer appends it. Both §16.6 profiles, from RECORD's fixture keys (record_presence_test.go).

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network where member m's laptop holds a live presence key of alg, and m has two more devices.
type testConfigPresenceNet struct {
	*testConfigNet
	member  Id
	laptop  testConfigDevice
	tablet  testConfigDevice
	phone   testConfigDevice
	key     *testPresenceKey
	tabletK *testPresenceKey
}

func newTestConfigPresenceNet(t *testing.T, alg bridge.KeyAlg) *testConfigPresenceNet {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	self := &testConfigPresenceNet{testConfigNet: net, member: member, laptop: laptop}
	self.tablet, self.phone = net.device("m tablet", member), net.device("m phone", member)
	net.admitDevice(laptop, self.tablet, 0)
	net.admitDevice(laptop, self.phone, 0)
	self.key = newTestPresenceKey(t, "m laptop key "+alg.String(), alg)
	self.tabletK = newTestPresenceKey(t, "m tablet key "+alg.String(), alg)
	net.registerPresenceKey(laptop, self.key)
	net.registerPresenceKey(self.tablet, self.tabletK)
	return self
}

// The act of signedBytes, each as a statement, countersigned by key as signer.
func testConfigAct(t testing.TB, key *testPresenceKey, signer testConfigDevice, signedBytes ...[]byte) []*testPresenceActStatement {
	statements := make([]*testPresenceActStatement, len(signedBytes))
	for i, statementBytes := range signedBytes {
		statements[i] = testConfigActStatement(t, statementBytes)
	}
	key.countersign(t, testGoodPresenceAssertion(), signer.sidecarId.Bytes(), statements)
	return statements
}

// Sequences one statement of an act.
func (self *testConfigNet) pushSigned(signed *bridge.Signed) ConfigVerdict {
	self.t.Helper()
	return self.push(self.makeEntry(bridge.AuthEntryKindStatement, testConfigMarshal(self.t, signed)))
}

// FS-124: the laptop's covered revocation of the phone is refused without its countersignature and with every wrong
// one, and lands with its own key's; the device's own sign-out needs none, and a countersignature on it is ignored.
func TestACoveredStatementNeedsItsSignersPresenceCountersignature(t *testing.T) {
	for _, alg := range []bridge.KeyAlg{bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256} {
		net := newTestConfigPresenceNet(t, alg)
		revoke := func() []byte {
			return net.sign(net.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
		}
		refuse := func(name string, signed *bridge.Signed) {
			t.Helper()
			if verdict := net.pushSigned(signed); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigPresence) {
				t.Errorf("%s, %s: %v", alg, name, verdict.Refusal)
			}
		}
		refuse("none", testConfigActStatement(t, revoke()).signed)
		unregistered := newTestPresenceKey(t, "never registered", alg)
		refuse("an unregistered key", testConfigAct(t, unregistered, net.laptop, revoke())[0].signed)
		refuse("another device's key", testConfigAct(t, net.tabletK, net.laptop, revoke())[0].signed)

		otherAct := testConfigAct(t, net.key, net.laptop, revoke(), revoke())
		spliced := testConfigActStatement(t, revoke()).signed
		spliced.Webauthn = otherAct[0].signed.GetWebauthn()
		refuse("another act's root", spliced)
		otherSigner := testConfigAct(t, net.key, net.tablet, revoke())[0].signed
		otherSigner.SignerId = net.laptop.sidecarId.Bytes()
		refuse("another signer's act", otherSigner)
		missing := testConfigAct(t, net.key, net.laptop, revoke(), revoke())[1].signed
		missing.Webauthn.ActPath = [][]byte{bytes.Repeat([]byte{0x5a}, 32)}
		refuse("a path that misses", missing)

		landed := net.pushSigned(testConfigAct(t, net.key, net.laptop, revoke())[0].signed)
		if !landed.Accepted() {
			t.Fatalf("%s: the countersigned revocation: %v", alg, landed.Refusal)
		}
		signOut := testConfigAct(t, unregistered, net.tablet, net.sign(net.tablet, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
			net.revocation(net.tablet, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)))[0].signed
		if verdict := net.pushSigned(signOut); !verdict.Accepted() {
			t.Errorf("%s: a sign-out with a countersignature the row does not ask: %v", alg, verdict.Refusal)
		}
		net.everyReaderAgrees()
	}
}

// A revoked or expired key countersigns nothing while its device holds another live key; once none is live, the row
// asks nothing.
func TestARevokedOrExpiredKeyCountersignsNothing(t *testing.T) {
	net := newTestConfigPresenceNet(t, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	second := newTestPresenceKey(t, "m laptop second key", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	register := net.presenceRegisterBody(net.member, second, second, net.timeMs+30*24*testConfigHourMs)
	registered := net.pushSigned(testConfigAct(t, net.key, net.laptop, net.signRaw(net.laptop, bridge.SignedType_SIGNED_KEY_REGISTER, register))[0].signed)
	if !registered.Accepted() {
		t.Fatalf("a second key, countersigned by the first: %v", registered.Refusal)
	}
	revokeFirst := net.sign(net.laptop, bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{Header: net.header(), KeyId: net.key.keyId})
	if verdict := net.pushSigned(testConfigAct(t, second, net.laptop, revokeFirst)[0].signed); !verdict.Accepted() {
		t.Fatalf("the first key's revocation: %v", verdict.Refusal)
	}
	revokePhone := net.sign(net.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	if verdict := net.pushSigned(testConfigAct(t, net.key, net.laptop, revokePhone)[0].signed); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigPresence) {
		t.Errorf("a revoked key's countersignature: %v", verdict.Refusal)
	}
	net.wait(31 * 24 * testConfigHourMs)
	if verdict := net.post(net.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)); !verdict.Accepted() {
		t.Errorf("with every key past its not_after, the row asks nothing: %v", verdict.Refusal)
	}
	net.everyReaderAgrees()
}

// §7.9's act: five statements countersigned once verify each alone, landing in any order, and an act of one too.
func TestAFiveStatementActVerifiesInAnyOrder(t *testing.T) {
	for _, alg := range []bridge.KeyAlg{bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256} {
		net := newTestConfigPresenceNet(t, alg)
		devices := []testConfigDevice{}
		for _, label := range []string{"a", "b", "c", "d", "e"} {
			device := net.device("m extra "+label, net.member)
			net.admitDevice(net.owner, device, 0)
			devices = append(devices, device)
		}
		signed := [][]byte{}
		for _, device := range devices {
			signed = append(signed, net.sign(net.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)))
		}
		act := testConfigAct(t, net.key, net.laptop, signed...)
		for _, i := range []int{3, 0, 4, 2, 1} {
			if verdict := net.pushSigned(act[i].signed); !verdict.Accepted() {
				t.Errorf("%s: statement %d: %v", alg, i, verdict.Refusal)
			}
		}
		alone := net.sign(net.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
		if verdict := net.pushSigned(testConfigAct(t, net.key, net.laptop, alone)[0].signed); !verdict.Accepted() {
			t.Errorf("%s: an act of one: %v", alg, verdict.Refusal)
		}
		net.everyReaderAgrees()
	}
}

// FS-124's thief: holding the laptop's identity key but not its presence key, it registers no key of its own,
// revokes no device and admits no untagged one, at every reader, though a malicious sequencer appends each; an
// uncovered tagged admission still lands.
func TestAThiefWithoutThePresenceKeyGetsNothingCovered(t *testing.T) {
	net := newTestConfigPresenceNet(t, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	thiefKey := newTestPresenceKey(t, "the thief's key", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	register := net.presenceRegisterBody(net.member, thiefKey, thiefKey, net.timeMs+30*24*testConfigHourMs)
	attempts := []struct {
		name   string
		signed []byte
	}{
		{name: "its own presence key", signed: net.signRaw(net.laptop, bridge.SignedType_SIGNED_KEY_REGISTER, register)},
		{name: "a revocation", signed: net.sign(net.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.tablet, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))},
		{name: "a compromise", signed: net.sign(net.laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(net.tablet, 1))},
		{name: "a device", signed: net.sign(net.laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(net.device("thief's device", net.member), nil, false, 0, 0))},
		{name: "a rebind", signed: net.sign(net.laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(testConfigRecovery(net.member, "thief")))},
	}
	for _, attempt := range attempts {
		if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, attempt.signed)); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigPresence) {
			t.Errorf("%s: %v", attempt.name, verdict.Refusal)
		}
	}
	if !net.log.State().PresenceRequired(&SidecarStatement{SignerId: net.laptop.sidecarId, Type: bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		Body: testConfigMarshal(t, net.revocation(net.tablet, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))}) {
		t.Error("PresenceRequired does not ask for the revocation's countersignature")
	}
	if net.log.State().PresenceRequired(&SidecarStatement{SignerId: net.owner.sidecarId, Type: bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		Body: testConfigMarshal(t, net.revocation(net.tablet, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))}) {
		t.Error("PresenceRequired asks it of a signer with no live key")
	}
	net.everyReaderAgrees()
}

// A key a device registered while a cascade's P held it is void, whatever lifts the device's park: it countersigns
// nothing, and once the device registers another key from outside P, the row asks that one's.
func TestAVoidedKeyCountersignsNothing(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, tablet, watch := net.device("m phone", member), net.device("m tablet", member), net.device("m watch", member)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(laptop, watch, 0)
	sinceN := net.n + 1
	net.admitDevice(phone, tablet, 0)
	voided := newTestPresenceKey(t, "m tablet key in P", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	net.registerPresenceKey(tablet, voided)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	net.mustPost(laptop, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: tablet.sidecarId.Bytes()})
	if live := net.log.State().LiveKeys(tablet.sidecarId); len(live) != 0 {
		t.Fatalf("a key registered in P is live: %v", live)
	}
	net.presenceKeys[tablet.sidecarId] = nil
	fresh := newTestPresenceKey(t, "m tablet key after the lift", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	net.registerPresenceKey(tablet, fresh)
	revokeWatch := net.sign(tablet, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(watch, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	if verdict := net.pushSigned(testConfigAct(t, voided, tablet, revokeWatch)[0].signed); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigPresence) {
		t.Errorf("a voided key's countersignature: %v", verdict.Refusal)
	}
	if verdict := net.pushSigned(testConfigAct(t, fresh, tablet, revokeWatch)[0].signed); !verdict.Accepted() {
		t.Errorf("the key registered after the lift: %v", verdict.Refusal)
	}
	net.everyReaderAgrees()
}
