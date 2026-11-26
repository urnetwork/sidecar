//go:build !ios_extension && !sidecar_http

// The release key's own signature over SHA256SUMS (CSRV-M11-02; DESIGN §4.10): testdata/attest/policy/'s sums and
// their signature by the test release key verify, and each refusal is its own: no key pinned, another key, another
// namespace, a certified key, other bytes and a signature that is not an SSHSIG.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A refusal for want's reason, wrapped beside ErrComputeReleaseSignatureRefused.
func testComputeReleaseWantRefused(t *testing.T, err error, want error) {
	t.Helper()
	if !errors.Is(err, ErrComputeReleaseSignatureRefused) || !errors.Is(err, want) {
		t.Fatalf("got %v; want a refusal for %v", err, want)
	}
}

// The sums the test release key signed under ur-release verify against it.
func TestComputeReleaseSignatureVerifies(t *testing.T) {
	keys := newTestAttestKeys(t)
	err := VerifyComputeReleaseSignature(testAttestVector(t, "SHA256SUMS"), testAttestVector(t, "SHA256SUMS.sig"),
		[]ssh.PublicKey{keys.otherRelease.PublicKey(), keys.release.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	sums := []byte("0000000000000000000000000000000000000000000000000000000000000001  infer_manifest.json\n")
	if err := VerifyComputeReleaseSignature(sums, testAttestSign(t, keys.release, computeReleaseNamespace, sums), []ssh.PublicKey{keys.release.PublicKey()}); err != nil {
		t.Fatal(err)
	}
}

// With no key pinned, as a source build pins none, even a good signature is refused for want of a key.
func TestComputeReleaseSignatureRefusesWithNoKey(t *testing.T) {
	for _, releaseKeys := range [][]ssh.PublicKey{nil, {}} {
		err := VerifyComputeReleaseSignature(testAttestVector(t, "SHA256SUMS"), testAttestVector(t, "SHA256SUMS.sig"), releaseKeys)
		testComputeReleaseWantRefused(t, err, ErrComputeReleaseKeyAbsent)
	}
	if computePolicyReleaseKeys == "" && len(ComputeReleaseKeys()) != 0 {
		t.Fatal("a build with an empty pin reads a release key")
	}
}

// A signature by a key no pin names: another release key, and the pinned key's own certificate presented as a pin.
func TestComputeReleaseSignatureRefusesAnotherKey(t *testing.T) {
	keys := newTestAttestKeys(t)
	err := VerifyComputeReleaseSignature(testAttestVector(t, "SHA256SUMS"), testAttestVector(t, "SHA256SUMS.sig"),
		[]ssh.PublicKey{keys.otherRelease.PublicKey()})
	testComputeReleaseWantRefused(t, err, errComputeReleaseKey)
	err = VerifyComputeReleaseSignature(testAttestVector(t, "SHA256SUMS"), testAttestVector(t, "SHA256SUMS.sig"),
		[]ssh.PublicKey{keys.policy.PublicKey()})
	testComputeReleaseWantRefused(t, err, errComputeReleaseKey)
}

// The release key signing the sums under a policy namespace, and a policy's own signature, never pass for the sums.
func TestComputeReleaseSignatureRefusesAnotherNamespace(t *testing.T) {
	keys := newTestAttestKeys(t)
	pinned := []ssh.PublicKey{keys.release.PublicKey()}
	sums := testAttestVector(t, "SHA256SUMS")
	err := VerifyComputeReleaseSignature(sums, testAttestSign(t, keys.release, ComputePolicyNamespace, sums), pinned)
	testComputeReleaseWantRefused(t, err, errComputeReleaseNamespace)
	err = VerifyComputeReleaseSignature(testAttestPolicyDocument(t), testAttestVector(t, "policy.json.sig"), pinned)
	testComputeReleaseWantRefused(t, err, errComputeReleaseNamespace)
}

// A key the release key certified signs under ur-release: still not the release key itself.
func TestComputeReleaseSignatureRefusesACertifiedKey(t *testing.T) {
	keys := newTestAttestKeys(t)
	sums := testAttestVector(t, "SHA256SUMS")
	err := VerifyComputeReleaseSignature(sums, testAttestSign(t, keys.policy, computeReleaseNamespace, sums),
		[]ssh.PublicKey{keys.release.PublicKey()})
	testComputeReleaseWantRefused(t, err, errComputeReleaseCertified)
}

// The good signature over other bytes: the sums with one line changed.
func TestComputeReleaseSignatureRefusesOtherBytes(t *testing.T) {
	keys := newTestAttestKeys(t)
	sums := testAttestVector(t, "SHA256SUMS")
	tampered := bytes.Replace(sums, []byte("0000"), []byte("1111"), 1)
	err := VerifyComputeReleaseSignature(tampered, testAttestVector(t, "SHA256SUMS.sig"), []ssh.PublicKey{keys.release.PublicKey()})
	testComputeReleaseWantRefused(t, err, errComputeReleaseSignature)
}

// A signature that is no armored SSHSIG.
func TestComputeReleaseSignatureRefusesMalformedSignatures(t *testing.T) {
	keys := newTestAttestKeys(t)
	good := testAttestVector(t, "SHA256SUMS.sig")
	for _, signature := range [][]byte{
		nil,
		[]byte("not a signature"),
		bytes.Replace(good, []byte("SSH SIGNATURE"), []byte("SSH SIGNATURF"), 1),
		good[:len(good)/2],
	} {
		err := VerifyComputeReleaseSignature(testAttestVector(t, "SHA256SUMS"), signature, []ssh.PublicKey{keys.release.PublicKey()})
		testComputeReleaseWantRefused(t, err, errComputeSshsigFormat)
	}
}
