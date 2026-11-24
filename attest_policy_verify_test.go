//go:build !ios_extension && !sidecar_http

// The verifier against testdata/attest/policy/'s vectors (ATTEST-M11-01): the good policy, then each refusal §5.4 and
// compute-plan-policy-signature-format's answer name, each in its own test, each refused for its own reason.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The vector's signature, verified at testAttestNow by a production build's verifier over the test release key.
func testAttestVerify(t *testing.T, signatureName string, staging bool) (*ComputePolicy, error) {
	t.Helper()
	return newTestAttestKeys(t).verifier(staging).Verify(testAttestPolicyDocument(t), testAttestVector(t, signatureName), testAttestNow)
}

// A refusal for want's reason, wrapped in ErrComputePolicyRefused.
func testAttestWantRefused(t *testing.T, policy *ComputePolicy, err error, want error) {
	t.Helper()
	if policy != nil || !errors.Is(err, ErrComputePolicyRefused) || !errors.Is(err, want) {
		t.Fatalf("got %v, %v; want a refusal for %v", policy, err, want)
	}
}

// policy.json under its certified key's signature verifies, and parses to what the document says.
func TestComputePolicyVerifies(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.sig", false)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Version != 3 || policy.NotAfterMs != 1801440000000 || !policy.Current(testAttestNow) {
		t.Errorf("version %d, not_after %d, current %t", policy.Version, policy.NotAfterMs, policy.Current(testAttestNow))
	}
	if !bytes.Equal(policy.Document(), testAttestPolicyDocument(t)) || !bytes.Equal(policy.Signature(), testAttestVector(t, "policy.json.sig")) {
		t.Error("the policy does not hold the bytes verified")
	}
	signer := policy.Signer()
	keys := newTestAttestKeys(t)
	if signer.Namespace != ComputePolicyNamespace || signer.Fingerprint != ssh.FingerprintSHA256(keys.policyKey.PublicKey()) || signer.Serial != 1 {
		t.Errorf("signer %+v", signer)
	}
	tee := policy.Provider("teetest")
	if tee == nil || tee.Label != ComputeLabelAp || tee.ProviderModelId("test-model-27b") != "chute-test-0001" || tee.Profile("teetest-2026.11.1") == nil {
		t.Errorf("teetest's line %+v", tee)
	}
	direct := policy.DirectProvider("directtest")
	if direct == nil || direct.Model("test-model-35b") == nil || !direct.Model("test-model-35b").ZeroRetention {
		t.Errorf("directtest's line %+v", direct)
	}
	if !policy.LimitedUse("teetest", "test-model-27b") || !policy.LimitedUse("directtest", "test-model-35b") || policy.LimitedUse("directtest", "other") {
		t.Error("limited_use does not read as one list over every provider's models")
	}
	if !policy.ProfileRevoked("teetest-2026.10.1") || policy.ProfileRevoked("teetest-2026.11.1") || !policy.GpuSerialRevoked("TEST-GPU-0001") ||
		!policy.ChipRevoked(ComputePolicyChipAmdChipId, policy.Revoked.Chips[0].Id) {
		t.Error("the revoked line does not read as written")
	}
}

// A policy signed under a namespace not this build's: ssh-keygen's file, and the release key's own.
func TestComputePolicyRefusesWrongNamespace(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.wrong-namespace.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyNamespace)
	policy, err = testAttestVerify(t, "policy.json.release-namespace.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyNamespace)
}

// The staging key's signature, valid under its own namespace, never passes in a production build.
func TestComputePolicyRefusesStagingSignedInProduction(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.staging.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyNamespace)
	if _, err := testAttestVerify(t, "policy.json.staging.sig", true); err != nil {
		t.Errorf("a staging build refused the staging key's policy: %v", err)
	}
}

// And the production policy never passes in a staging or CI build.
func TestComputePolicyRefusesProductionSignedInStaging(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.sig", true)
	testAttestWantRefused(t, policy, err, errComputePolicyNamespace)
}

// A key certified for ur-compute-policy by a key no build pins.
func TestComputePolicyRefusesCertificateByAnotherKey(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.other-authority.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyAuthority)
}

// A certificate past its validity, and one not valid yet.
func TestComputePolicyRefusesCertificatePastItsValidity(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.expired.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyValidity)
	policy, err = testAttestVerify(t, "policy.json.not-yet.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyValidity)
}

// A certificate valid for longer than a year, or forever, though valid now.
func TestComputePolicyRefusesCertificateValidPastAYear(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.long.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyValidity)
	policy, err = testAttestVerify(t, "policy.json.forever.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyValidity)
}

// A certificate naming the staging namespace as its principal, or both, signing under the production namespace.
func TestComputePolicyRefusesCertificateNamingAnotherPrincipal(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.staging-principal.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyPrincipal)
	policy, err = testAttestVerify(t, "policy.json.two-principals.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyPrincipal)
}

// A host certificate, and a certificate carrying a critical option, from the pinned key.
func TestComputePolicyRefusesOtherCertificateForms(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.host-certificate.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyValidity)
	policy, err = testAttestVerify(t, "policy.json.critical-option.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyCriticalOption)
}

// The release key itself signing a policy, under the policy's own namespace, is a bare key and refused; its own
// signature over SHA256SUMS, under ur-release, never passes for a policy.
func TestComputePolicyRefusesReleaseKeySignature(t *testing.T) {
	policy, err := testAttestVerify(t, "policy.json.release-key.sig", false)
	testAttestWantRefused(t, policy, err, errComputePolicyNotCertified)
	verifier := newTestAttestKeys(t).verifier(false)
	policy, err = verifier.Verify(testAttestVector(t, "SHA256SUMS"), testAttestVector(t, "SHA256SUMS.sig"), testAttestNow)
	testAttestWantRefused(t, policy, err, errComputePolicyNamespace)
	policy, err = verifier.Verify(testAttestPolicyDocument(t), testAttestVector(t, "SHA256SUMS.sig"), testAttestNow)
	testAttestWantRefused(t, policy, err, errComputePolicyNamespace)
}

// The policy's good signature presented over SHA256SUMS's bytes, and over the policy with one byte changed.
func TestComputePolicyRefusesSignatureOverOtherBytes(t *testing.T) {
	verifier := newTestAttestKeys(t).verifier(false)
	signature := testAttestVector(t, "policy.json.sig")
	policy, err := verifier.Verify(testAttestVector(t, "SHA256SUMS"), signature, testAttestNow)
	testAttestWantRefused(t, policy, err, errComputePolicySignature)
	tampered := testAttestPolicyEdit(t, `"version": 3,`, `"version": 9,`)
	policy, err = verifier.Verify(tampered, signature, testAttestNow)
	testAttestWantRefused(t, policy, err, errComputePolicySignature)
}

// A build from this tree pins no release key, so the good policy, and every other, is refused: the fail-closed
// state until the key ceremony writes RELEASE-KEY.pub's line into attest_policy_root.go. A production build pins the
// production namespace alone, and a sidecar_compute_staging build the staging one.
func TestComputePolicyBuildWithNoRootRefusesEveryPolicy(t *testing.T) {
	if computePolicyReleaseKeys != "" {
		t.Skip("this build pins a release key")
	}
	verifier := NewComputePolicyVerifier(DefaultAttestSettings())
	want := ComputePolicyNamespace
	if computePolicyStagingBuild {
		want = ComputePolicyStagingNamespace
	}
	if verifier.Namespace() != want || verifier.Staging() != computePolicyStagingBuild {
		t.Errorf("this build verifies %q, staging %t", verifier.Namespace(), verifier.Staging())
	}
	for _, name := range []string{"policy.json.sig", "policy.json.staging.sig", "policy.json.release-key.sig"} {
		policy, err := verifier.Verify(testAttestPolicyDocument(t), testAttestVector(t, name), testAttestNow)
		testAttestWantRefused(t, policy, err, errComputePolicyNoRoot)
	}
}

// A signature that is not an armored SSHSIG, in each way the armor and blob can fail.
func TestComputePolicyRefusesMalformedSignatures(t *testing.T) {
	verifier := newTestAttestKeys(t).verifier(false)
	good := testAttestVector(t, "policy.json.sig")
	cases := map[string][]byte{
		"empty":           {},
		"no armor":        bytes.TrimPrefix(good, []byte(computeSshsigBegin+"\n")),
		"crlf":            bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n")),
		"bytes before":    append([]byte("x"), good...),
		"bytes after":     append(bytes.Clone(good), "x"...),
		"a blank line":    bytes.Replace(good, []byte("\n"), []byte("\n\n"), 2),
		"bad base64":      bytes.Replace(good, []byte("U1NI"), []byte("U1N*"), 1),
		"truncated":       append(append([]byte{}, good[:len(good)/2]...), []byte("\n"+computeSshsigEnd+"\n")...),
		"another magic":   bytes.Replace(good, []byte("U1NIU0lH"), []byte("U1NIU0lI"), 1),
		"a space in body": bytes.Replace(good, []byte("\nAg"), []byte("\n Ag"), 1),
	}
	for name, signature := range cases {
		policy, err := verifier.Verify(testAttestPolicyDocument(t), signature, testAttestNow)
		if policy != nil || !errors.Is(err, ErrComputePolicyRefused) {
			t.Errorf("%s: %v, %v", name, policy, err)
		}
	}
	if _, err := verifier.Verify(testAttestPolicyDocument(t), bytes.Clone(good[:len(good)-1]), testAttestNow); err != nil {
		t.Errorf("an armor without its final newline: %v", err)
	}
}

// The sizes bound the work before anything is parsed.
func TestComputePolicyRefusesOversizeInputs(t *testing.T) {
	keys := newTestAttestKeys(t)
	settings := DefaultAttestSettings()
	document := testAttestPolicyDocument(t)
	signature := testAttestVector(t, "policy.json.sig")
	settings.PolicyMaxByteCount = len(document) - 1
	verifier := newComputePolicyVerifier(settings, []ssh.PublicKey{keys.release.PublicKey()}, ComputePolicyNamespace, false)
	policy, err := verifier.Verify(document, signature, testAttestNow)
	testAttestWantRefused(t, policy, err, errComputePolicyTooLarge)
	settings = DefaultAttestSettings()
	settings.SignatureMaxByteCount = len(signature) - 1
	verifier = newComputePolicyVerifier(settings, []ssh.PublicKey{keys.release.PublicKey()}, ComputePolicyNamespace, false)
	policy, err = verifier.Verify(document, signature, testAttestNow)
	testAttestWantRefused(t, policy, err, errComputePolicyTooLarge)
}

// A signature this file makes is the one ssh-keygen would: the armor round-trips through the parser to the same
// key, namespace and hash, under both the certified key and a bare one.
func TestComputeSshsigRoundTrips(t *testing.T) {
	keys := newTestAttestKeys(t)
	for _, signer := range []ssh.Signer{keys.policy, keys.release} {
		armored := testAttestSign(t, signer, ComputePolicyNamespace, []byte("message"))
		parsed, err := computeSshsigParse(armored)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.namespace != ComputePolicyNamespace || parsed.hashAlgorithm != computeSshsigHashSha512 ||
			!bytes.Equal(parsed.publicKey.Marshal(), signer.PublicKey().Marshal()) {
			t.Errorf("parsed %+v", parsed)
		}
		signed, err := computeSshsigSignedData(parsed.namespace, parsed.hashAlgorithm, []byte("message"))
		if err != nil {
			t.Fatal(err)
		}
		if err := signer.PublicKey().Verify(signed, parsed.signature); err != nil {
			t.Errorf("the signature does not verify: %v", err)
		}
	}
}
