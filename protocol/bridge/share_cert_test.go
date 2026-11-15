package bridge

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
)

// A share's keys, fixed for the tests: the ShareKey, two generations' ShareSigners, and another share's key.
var (
	testShareId         = bytes.Repeat([]byte{0x5e}, 16)
	testShareSeed       = bytes.Repeat([]byte{0x61}, ed25519.SeedSize)
	testShareKey        = ed25519.NewKeyFromSeed(testShareSeed)
	testShareSignerSeed = bytes.Repeat([]byte{0x62}, ed25519.SeedSize)
	testShareOtherSeed  = bytes.Repeat([]byte{0x63}, ed25519.SeedSize)
)

// A cert of generation g for the signer seed, running lifetimeMs from the tests' now.
func testShareCert(t testing.TB, generation uint64, signerSeed []byte, lifetimeMs int64) []byte {
	t.Helper()
	signed, err := ShareCertSigned(&ShareCert{
		ShareId: testShareId, ConfigGeneration: generation,
		SignerPublicKey: ed25519.NewKeyFromSeed(signerSeed).Public().(ed25519.PublicKey),
		NotAfterMs:      testDelegationNowMs + lifetimeMs,
	}, testShareSeed, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testShareCertCheck(generation uint64) *ShareCertCheck {
	return &ShareCertCheck{
		ShareId: testShareId, SharePublicKey: testShareKey.Public().(ed25519.PublicKey), NowMs: testDelegationNowMs, Generation: generation,
	}
}

// A share link's delegation, signed by the signer seed under cert.
func testShareDelegation(t testing.TB, cert []byte, signerSeed []byte, edit func(delegation *WindowDelegation)) []byte {
	t.Helper()
	delegation := testDelegation()
	delegation.ShareId, delegation.ShareCert = testShareId, cert
	if edit != nil {
		edit(delegation)
	}
	signed, err := WindowDelegationSigned(delegation, func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
		return ShareSignerSign(testShareId, signerSeed, body)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// The check a share host makes: the same-network row's values, and the share's pinned key and ratchet.
func testShareDelegationCheck(generation uint64) *WindowDelegationCheck {
	check := testDelegationCheck()
	check.Share = func(shareId []byte) (*WindowDelegationShare, bool) {
		if !bytes.Equal(shareId, testShareId) {
			return nil, false
		}
		return &WindowDelegationShare{SharePublicKey: testShareKey.Public().(ed25519.PublicKey), Generation: generation}, true
	}
	return check
}

// §17.9's admit row, its first half: a ShareCert verifies under the pinned ShareKey for its share, with not_after
// ahead and at most 7 days and §8.6's skew away, at a generation no lower than the share's ratchet.
func TestVerifyShareCertHoldsItsRow(t *testing.T) {
	week := int64(testDelegationWeekMs)
	cert, err := VerifyShareCert(testShareCert(t, 7, testShareSignerSeed, week), testShareCertCheck(7))
	if err != nil || cert.GetConfigGeneration() != 7 {
		t.Fatalf("a current certificate: %v", err)
	}
	if _, err := VerifyShareCert(testShareCert(t, 8, testShareSignerSeed, week+60_000), testShareCertCheck(7)); err != nil {
		t.Errorf("a newer generation inside the skew: %v", err)
	}

	otherShare := testShareCertCheck(7)
	otherShare.ShareId = testDelegationOtherId
	otherKey := testShareCertCheck(7)
	otherKey.SharePublicKey = ed25519.NewKeyFromSeed(testShareOtherSeed).Public().(ed25519.PublicKey)
	byOther, _ := ShareCertSigned(&ShareCert{
		ShareId: testShareId, ConfigGeneration: 7, SignerPublicKey: testShareKey.Public().(ed25519.PublicKey), NotAfterMs: testDelegationNowMs + week,
	}, testShareOtherSeed, nil)
	flipped := testShareCert(t, 7, testShareSignerSeed, week)
	flipped[len(flipped)/2] ^= 0x01
	small := testShareCertCheck(7)
	small.Settings = &ShareCertSettings{MaxByteCount: 32, Lifetime: DefaultShareCertSettings().Lifetime, Skew: DefaultShareCertSettings().Skew}
	for _, c := range []struct {
		name  string
		bytes []byte
		check *ShareCertCheck
		want  error
	}{
		{"below the ratchet", testShareCert(t, 6, testShareSignerSeed, week), testShareCertCheck(7), ErrShareCertGeneration},
		{"expired", testShareCert(t, 7, testShareSignerSeed, 0), testShareCertCheck(7), ErrShareCertExpired},
		{"over 7 days out", testShareCert(t, 7, testShareSignerSeed, week+60_001), testShareCertCheck(7), ErrShareCertLifetime},
		{"another share's check", testShareCert(t, 7, testShareSignerSeed, week), otherShare, ErrShareCertSigner},
		{"not the pinned ShareKey", testShareCert(t, 7, testShareSignerSeed, week), otherKey, ErrShareCertSigner},
		{"signed by another key under the pinned key's name", byOther, testShareCertCheck(7), ErrShareCertSigner},
		{"past the bound", testShareCert(t, 7, testShareSignerSeed, week), small, ErrShareCertMalformed},
		{"no bytes", nil, testShareCertCheck(7), ErrShareCertMalformed},
		{"no check", testShareCert(t, 7, testShareSignerSeed, week), &ShareCertCheck{}, ErrShareCertSigner},
	} {
		if _, err := VerifyShareCert(c.bytes, c.check); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := VerifyShareCert(flipped, testShareCertCheck(7)); err == nil {
		t.Error("a flipped byte verified")
	}
	// another statement of the ShareKey's is no certificate
	delegation := testShareDelegation(t, testShareCert(t, 7, testShareSignerSeed, week), testShareSeed, nil)
	if _, err := VerifyShareCert(delegation, testShareCertCheck(7)); !errors.Is(err, ErrSignedTypeMismatch) {
		t.Errorf("a delegation as a certificate: %v", err)
	}
}

// The admit row whole: a ShareSigner-signed delegation verifies under the cert's signer key, the cert under the
// pinned ShareKey, and the admission carries the cert, whose generation the host raises its ratchet to and whose
// not_after bounds the principal.
func TestAShareDelegationVerifiesUnderItsCertifiedSigner(t *testing.T) {
	week := int64(testDelegationWeekMs)
	cert := testShareCert(t, 7, testShareSignerSeed, week-1000)
	admission, err := VerifyWindowDelegationAdmission(testShareDelegation(t, cert, testShareSignerSeed, nil), testShareDelegationCheck(7))
	if err != nil {
		t.Fatal(err)
	}
	if admission.ShareCert.GetConfigGeneration() != 7 || !bytes.Equal(admission.ShareCertSigned, cert) || len(admission.ForwardDelegationId) != 0 {
		t.Fatalf("the admission: %+v", admission)
	}
	if !bytes.Equal(admission.Delegation.GetShareId(), testShareId) || admission.ShareCert.GetNotAfterMs() >= admission.Delegation.GetNotAfterMs() {
		t.Errorf("the delegation and its cert: %v, %v", admission.Delegation, admission.ShareCert)
	}

	otherSignerCert := testShareCert(t, 7, testShareOtherSeed, week)
	for _, c := range []struct {
		name  string
		bytes []byte
		check *WindowDelegationCheck
		want  error
	}{
		{"no share admitted", testShareDelegation(t, cert, testShareSignerSeed, nil), testDelegationCheck(), ErrWindowDelegationShare},
		{"a cert below the ratchet", testShareDelegation(t, cert, testShareSignerSeed, nil), testShareDelegationCheck(8), ErrShareCertGeneration},
		{"an expired cert", testShareDelegation(t, testShareCert(t, 7, testShareSignerSeed, 0), testShareSignerSeed, nil), testShareDelegationCheck(7), ErrShareCertExpired},
		{"a cert over 7 days out", testShareDelegation(t, testShareCert(t, 7, testShareSignerSeed, week+61_000), testShareSignerSeed, nil), testShareDelegationCheck(7), ErrShareCertLifetime},
		{"a signer the cert does not certify", testShareDelegation(t, otherSignerCert, testShareSignerSeed, nil), testShareDelegationCheck(7), ErrWindowDelegationSigner},
		{"another window client", testShareDelegation(t, cert, testShareSignerSeed, func(delegation *WindowDelegation) {
			delegation.WindowClientId = testDelegationOtherId
		}), testShareDelegationCheck(7), ErrWindowDelegationMismatch},
		{"another target", testShareDelegation(t, cert, testShareSignerSeed, func(delegation *WindowDelegation) {
			delegation.TargetSidecarId = testDelegationOtherId
		}), testShareDelegationCheck(7), ErrWindowDelegationMismatch},
		{"another network", testShareDelegation(t, cert, testShareSignerSeed, func(delegation *WindowDelegation) {
			delegation.NetworkId = testDelegationOtherNetwork
		}), testShareDelegationCheck(7), ErrWindowDelegationMismatch},
		{"an expired delegation", testShareDelegation(t, cert, testShareSignerSeed, func(delegation *WindowDelegation) {
			delegation.NotAfterMs = testDelegationNowMs
		}), testShareDelegationCheck(7), ErrWindowDelegationExpired},
	} {
		if _, err := VerifyWindowDelegationAdmission(c.bytes, c.check); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	// a cert signed by a key that is not the pinned ShareKey certifies nothing, whatever it names
	forged, _ := ShareCertSigned(&ShareCert{
		ShareId: testShareId, ConfigGeneration: 9, SignerPublicKey: ed25519.NewKeyFromSeed(testShareOtherSeed).Public().(ed25519.PublicKey),
		NotAfterMs: testDelegationNowMs + week,
	}, testShareOtherSeed, nil)
	if _, err := VerifyWindowDelegationAdmission(testShareDelegation(t, forged, testShareOtherSeed, nil), testShareDelegationCheck(7)); !errors.Is(err, ErrShareCertSigner) {
		t.Errorf("a cert not by the pinned ShareKey: %v", err)
	}
	// a flipped byte of the delegation's body fails its signature
	flipped := &Signed{}
	if err := proto.Unmarshal(testShareDelegation(t, cert, testShareSignerSeed, nil), flipped); err != nil {
		t.Fatal(err)
	}
	flipped.Signature[3] ^= 0x01
	flippedBytes, _ := proto.Marshal(flipped)
	if _, err := VerifyWindowDelegationAdmission(flippedBytes, testShareDelegationCheck(7)); !errors.Is(err, ErrSignedSignature) {
		t.Errorf("a flipped signature: %v", err)
	}
}

// A share's fields ride only a share signer's delegation: an identity key's delegation that names a share is refused
// at the signer and at the verifier, a share signer's delegation without its certificate at both, and a share's
// delegation signed under another share's name at the signer.
func TestAShareRidesOnlyAShareSignersDelegation(t *testing.T) {
	cert := testShareCert(t, 7, testShareSignerSeed, testDelegationWeekMs)
	identitySign := func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
		return &Signed{
			Body: body, SignerId: testDelegationSubjectId, Type: uint32(signedType),
			Signature: ed25519.Sign(testDelegationSubjectKey, SignedBytes(purpose, signedType, body)),
		}, nil
	}
	shareSign := func(shareId []byte) func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
		return func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
			return ShareSignerSign(shareId, testShareSignerSeed, body)
		}
	}
	withShare := testDelegation()
	withShare.ShareId, withShare.ShareCert = testShareId, cert
	noCert := testDelegation()
	noCert.ShareId = testShareId
	for name, err := range map[string]error{
		"an identity key signing a share":   testDelegationSignError(WindowDelegationSigned(withShare, identitySign, nil)),
		"a share without its certificate":   testDelegationSignError(WindowDelegationSigned(noCert, shareSign(testShareId), nil)),
		"a share signed under another name": testDelegationSignError(WindowDelegationSigned(withShare, shareSign(testDelegationOtherId), nil)),
		"a share signer naming no share":    testDelegationSignError(WindowDelegationSigned(testDelegation(), shareSign(testShareId), nil)),
	} {
		if !errors.Is(err, ErrWindowDelegationShare) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the verifier refuses an identity-signed delegation that carries a share, built past the signer's own check
	body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(withShare)
	signed, _ := identitySign(SignedPurposeWindowDelegation, SignedType_SIGNED_WINDOW_DELEGATION, body)
	signedBytes, _ := proto.Marshal(signed)
	if _, err := VerifyWindowDelegationAdmission(signedBytes, testShareDelegationCheck(7)); !errors.Is(err, ErrWindowDelegationShare) {
		t.Errorf("an identity key's delegation carrying a share: %v", err)
	}
}

func testDelegationSignError(_ []byte, err error) error {
	return err
}
