// FixturePresenceKey's keys are the root vectors' keys for the same seeds, and what it signs, countersigns and
// registers verifies through the root's checks, with a spoiled flag refused, so a case built on it starts from evidence
// that passes for the reason it should.

package sidecartest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The root's vectors, relative to this package.
const fixturePresenceVectorsPath = "../testdata/presence/vectors.json"

// A member, a signer and an action, visibly synthetic.
var (
	fixturePresenceMemberId = bytes.Repeat([]byte{0x4d}, 16)
	fixturePresenceSignerId = bytes.Repeat([]byte{0x5d}, 16)
	fixturePresenceBody     = []byte("a synthetic approval decision")
)

// Both profiles' keys from one seed each.
func fixturePresenceKeys() []*FixturePresenceKey {
	return []*FixturePresenceKey{
		NewFixturePresenceKey("webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256),
		NewFixturePresenceKey("ecdsa-p256-sha256 key a", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256),
	}
}

func TestFixturePresenceKeyMatchesTheVectors(t *testing.T) {
	encoded, err := os.ReadFile(fixturePresenceVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	file := struct {
		Keys []struct {
			Seed      string `json:"seed"`
			Alg       string `json:"alg"`
			KeyId     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}{}
	if err := json.Unmarshal(encoded, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Keys) != 2 {
		t.Fatalf("%d keys in the vectors", len(file.Keys))
	}
	for _, vector := range file.Keys {
		alg := bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256
		if vector.Alg == "ecdsa-p256-sha256" {
			alg = bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256
		}
		key := NewFixturePresenceKey(vector.Seed, alg)
		if fmt.Sprintf("%x", key.KeyId) != vector.KeyId || fmt.Sprintf("%x", key.PublicKey) != vector.PublicKey {
			t.Errorf("%s: the fixture derives another key than the vectors", vector.Seed)
		}
	}
}

// Each use verifies, the next one's count moves on, and a replay to the same store is refused.
func TestFixturePresenceKeySignsUses(t *testing.T) {
	for _, key := range fixturePresenceKeys() {
		row := key.KeyRow(fixturePresenceMemberId, fixturePresenceSignerId, 3)
		counter := NewFakePresenceCounter()
		first := key.Sign(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, fixturePresenceBody)
		second := key.Sign(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, fixturePresenceBody)
		for _, signed := range []*bridge.Signed{first, second} {
			err := sidecar.VerifyPresenceUse(signed, sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, row, counter)
			if err != nil {
				t.Errorf("%s: %v", key.Alg, err)
			}
		}
		err := sidecar.VerifyPresenceUse(first, sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, row, counter)
		if key.Alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			if !errors.Is(err, sidecar.ErrPresenceCounter) {
				t.Errorf("the replay: %v", err)
			}
			if count := counter.Count(key.KeyId); count != 2 {
				t.Errorf("count %d, want 2", count)
			}
		} else if err != nil {
			// ecdsa-p256-sha256 has no counter, and its replay is the nonce's and the ledger's to refuse
			t.Errorf("%s: %v", key.Alg, err)
		}
	}
}

// A failing store refuses the use.
func TestFakePresenceCounterFails(t *testing.T) {
	key := NewFixturePresenceKey("webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	counter := NewFakePresenceCounter()
	storeFailed := errors.New("a store that cannot write")
	counter.SetErr(storeFailed)
	signed := key.Sign(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, fixturePresenceBody)
	row := key.KeyRow(fixturePresenceMemberId, fixturePresenceSignerId, 3)
	err := sidecar.VerifyPresenceUse(signed, sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, row, counter)
	if !errors.Is(err, storeFailed) {
		t.Errorf("%v", err)
	}
}

// A five-statement act verifies statement by statement; with UV clear, a webauthn-es256 act is refused.
func TestFixturePresenceKeyCountersignsAnAct(t *testing.T) {
	act := func() []*FixturePresenceStatement {
		statements := []*FixturePresenceStatement{}
		for i, signedType := range []bridge.SignedType{
			bridge.SignedType_SIGNED_SIDECAR_REVOKE,
			bridge.SignedType_SIGNED_KEY_REVOKE,
			bridge.SignedType_SIGNED_RECOVERY_VETO,
			bridge.SignedType_SIGNED_MEMBER_REVOKE,
			bridge.SignedType_SIGNED_ADMIN_SET,
		} {
			statements = append(statements, &FixturePresenceStatement{
				Purpose: bridge.SignedPurposeAuthority,
				Signed:  &bridge.Signed{Body: fmt.Appendf(nil, "synthetic covered statement %d", i), Type: uint32(signedType)},
			})
		}
		return statements
	}
	for _, key := range fixturePresenceKeys() {
		row := key.KeyRow(fixturePresenceMemberId, fixturePresenceSignerId, 3)
		statements := act()
		if err := key.Countersign(fixturePresenceSignerId, statements); err != nil {
			t.Fatal(err)
		}
		for i, statement := range statements {
			if err := sidecar.VerifyPresenceCountersignature(statement.Signed, statement.Purpose, row); err != nil {
				t.Errorf("%s, statement %d: %v", key.Alg, i, err)
			}
		}
		if key.Alg != bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			continue
		}
		key.Flags = FixturePresenceFlagUserPresent
		spoiled := act()
		if err := key.Countersign(fixturePresenceSignerId, spoiled); err != nil {
			t.Fatal(err)
		}
		err := sidecar.VerifyPresenceCountersignature(spoiled[0].Signed, spoiled[0].Purpose, row)
		if !errors.Is(err, bridge.ErrSignedEvidence) {
			t.Errorf("UV clear: %v", err)
		}
	}
}

// RegisterBody's body parses as the log parses a KeyRegister and its proof verifies; the caller's register is left as
// it was.
func TestFixturePresenceKeyRegisters(t *testing.T) {
	for _, key := range fixturePresenceKeys() {
		register := &protocol.KeyRegister{
			Header:   &bridge.StatementHeader{NetworkId: bytes.Repeat([]byte{0x4e}, 16), Nonce: bytes.Repeat([]byte{0x6e}, 16)},
			MemberId: fixturePresenceMemberId,
			NotAfter: 1798761600000,
		}
		body, err := key.RegisterBody(register)
		if err != nil {
			t.Fatal(err)
		}
		if len(register.GetKeyId()) != 0 || len(register.GetKeySignature()) != 0 {
			t.Errorf("%s: RegisterBody changed its argument", key.Alg)
		}
		message, err := sidecar.ParseConfigStatement(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_KEY_REGISTER, body)
		if err != nil {
			t.Fatal(err)
		}
		parsed := message.(*protocol.KeyRegister)
		if !bytes.Equal(parsed.GetPublicKey(), key.PublicKey) || len(parsed.GetKeySignature()) == 0 {
			t.Errorf("%s: the body registers another key, or no proof", key.Alg)
		}
		signed := &bridge.Signed{Body: body, SignerId: fixturePresenceSignerId, Type: uint32(bridge.SignedType_SIGNED_KEY_REGISTER)}
		if err := sidecar.VerifyPresenceRegistration(parsed, signed); err != nil {
			t.Errorf("%s: %v", key.Alg, err)
		}
	}
}
