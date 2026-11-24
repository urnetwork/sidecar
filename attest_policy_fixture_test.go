//go:build !ios_extension && !sidecar_http

// The compute policy's test keys and vectors (ATTEST-M11-01): a test release key that certifies a test compute-policy
// key and a test staging key, every key from a fixed seed and every certificate's nonce from a fixed stream, so each
// signature in testdata/attest/policy/ repeats byte for byte. TestComputePolicyVectorsAreCurrent holds the committed
// files to what these make; SIDECAR_WRITE_ATTEST_VECTORS=1 rewrites them, as after the format changes before it
// freezes. No production build trusts any of these keys: its verifier pins the release key alone.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The instant the vectors are judged at: inside every good test certificate's window, before policy.json's
// not_after, and after its disclosures took effect.
var testAttestNow = time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)

const (
	testAttestVectorDirectory         = "testdata/attest/policy"
	testAttestWriteVectorsEnvironment = "SIDECAR_WRITE_ATTEST_VECTORS"
)

// A deterministic stream: SHA-256 of label and a counter, block after block.
type testAttestStream struct {
	label   string
	counter uint64
	buffer  []byte
}

func (self *testAttestStream) Read(out []byte) (int, error) {
	for len(self.buffer) < len(out) {
		block := sha256.New()
		block.Write([]byte(self.label))
		binary.Write(block, binary.BigEndian, self.counter)
		self.counter += 1
		self.buffer = block.Sum(self.buffer)
	}
	count := copy(out, self.buffer)
	self.buffer = self.buffer[count:]
	return count, nil
}

// A stream that repeats for label.
func testAttestRandom(label string) io.Reader {
	return &testAttestStream{label: "urnetwork-sidecar test attest stream " + label}
}

// An Ed25519 key from label, the same every run.
func testAttestKey(t testing.TB, label string) ssh.Signer {
	t.Helper()
	seed := sha256.Sum256([]byte("urnetwork-sidecar test attest key " + label))
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// What a test certificate says.
type testAttestCertificate struct {
	principals  []string
	validAfter  time.Time
	validBefore time.Time
	// Forever where set: valid_before is OpenSSH's infinity.
	forever         bool
	certType        uint32
	criticalOptions map[string]string
}

// The good certificate's window: 2026-11-01 for 364 days, inside a year.
func testAttestGoodWindow() (time.Time, time.Time) {
	validAfter := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	return validAfter, validAfter.Add(364 * 24 * time.Hour)
}

// key with an OpenSSH certificate authority signed as certificate says, as a signer whose public key is the
// certificate.
func testAttestCertify(t testing.TB, key ssh.Signer, authority ssh.Signer, certificate testAttestCertificate) ssh.Signer {
	t.Helper()
	certType := certificate.certType
	if certType == 0 {
		certType = ssh.UserCert
	}
	validBefore := uint64(certificate.validBefore.Unix())
	if certificate.forever {
		validBefore = ssh.CertTimeInfinity
	}
	criticalOptions := certificate.criticalOptions
	if criticalOptions == nil {
		criticalOptions = map[string]string{}
	}
	cert := &ssh.Certificate{
		Key:             key.PublicKey(),
		Serial:          1,
		CertType:        certType,
		KeyId:           "attest test " + strings.Join(certificate.principals, " "),
		ValidPrincipals: certificate.principals,
		ValidAfter:      uint64(certificate.validAfter.Unix()),
		ValidBefore:     validBefore,
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      map[string]string{},
		},
	}
	if err := cert.SignCert(testAttestRandom("certificate "+cert.KeyId), authority); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// The test keys: the release key and one no build pins, and the compute-policy and staging keys bare and certified.
type testAttestKeys struct {
	release      ssh.Signer
	otherRelease ssh.Signer
	policyKey    ssh.Signer
	stagingKey   ssh.Signer
	// The compute-policy key, certified by release for ur-compute-policy alone.
	policy ssh.Signer
	// The staging key, certified by release for ur-compute-policy-staging alone.
	staging ssh.Signer
}

func newTestAttestKeys(t testing.TB) *testAttestKeys {
	t.Helper()
	validAfter, validBefore := testAttestGoodWindow()
	keys := &testAttestKeys{
		release:      testAttestKey(t, "release"),
		otherRelease: testAttestKey(t, "other release"),
		policyKey:    testAttestKey(t, "compute policy"),
		stagingKey:   testAttestKey(t, "staging"),
	}
	keys.policy = testAttestCertify(t, keys.policyKey, keys.release, testAttestCertificate{
		principals: []string{ComputePolicyNamespace}, validAfter: validAfter, validBefore: validBefore,
	})
	keys.staging = testAttestCertify(t, keys.stagingKey, keys.release, testAttestCertificate{
		principals: []string{ComputePolicyStagingNamespace}, validAfter: validAfter, validBefore: validBefore,
	})
	return keys
}

// A verifier that pins the test release key, as a production build (staging false) or a staging one.
func (self *testAttestKeys) verifier(staging bool) *ComputePolicyVerifier {
	namespace := ComputePolicyNamespace
	if staging {
		namespace = ComputePolicyStagingNamespace
	}
	return newComputePolicyVerifier(DefaultAttestSettings(), []ssh.PublicKey{self.release.PublicKey()}, namespace, staging)
}

// An armored SSHSIG over message by signer under namespace.
func testAttestSign(t testing.TB, signer ssh.Signer, namespace string, message []byte) []byte {
	t.Helper()
	signature, err := ComputeSshsigSign(testAttestRandom("sign"), signer, namespace, message)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

// policy.json, the vector document.
func testAttestPolicyDocument(t testing.TB) []byte {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(testAttestVectorDirectory, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// The vector document at version, its version line rewritten.
func testAttestPolicyVersion(t testing.TB, version int) []byte {
	t.Helper()
	document := testAttestPolicyDocument(t)
	rewritten := bytes.Replace(document, []byte(`"version": 3,`), []byte(`"version": `+strconv.Itoa(version)+`,`), 1)
	if bytes.Equal(rewritten, document) && version != 3 {
		t.Fatal("policy.json has no version line to rewrite")
	}
	return rewritten
}

// The vector document with old replaced by replacement once, which must be there.
func testAttestPolicyEdit(t testing.TB, old string, replacement string) []byte {
	t.Helper()
	document := testAttestPolicyDocument(t)
	if !bytes.Contains(document, []byte(old)) {
		t.Fatalf("policy.json does not hold %q", old)
	}
	return bytes.Replace(document, []byte(old), []byte(replacement), 1)
}

// SHA256SUMS as a release signs it: the release key's own file, under ur-release.
var testAttestSha256sums = []byte("0000000000000000000000000000000000000000000000000000000000000000  ur-test-linux-amd64.tar.gz\n")

// Every signature vector, by file name, as the keys make them.
func testAttestSignatureVectors(t testing.TB) map[string][]byte {
	t.Helper()
	keys := newTestAttestKeys(t)
	document := testAttestPolicyDocument(t)
	validAfter, validBefore := testAttestGoodWindow()
	certified := func(authority ssh.Signer, certificate testAttestCertificate) ssh.Signer {
		return testAttestCertify(t, keys.policyKey, authority, certificate)
	}
	good := testAttestCertificate{principals: []string{ComputePolicyNamespace}, validAfter: validAfter, validBefore: validBefore}
	expired := good
	expired.validAfter = time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	expired.validBefore = time.Date(2025, time.December, 31, 0, 0, 0, 0, time.UTC)
	notYet := good
	notYet.validAfter = time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	notYet.validBefore = time.Date(2027, time.December, 1, 0, 0, 0, 0, time.UTC)
	long := good
	long.validBefore = validAfter.Add(2 * 366 * 24 * time.Hour)
	forever := good
	forever.forever = true
	stagingPrincipal := good
	stagingPrincipal.principals = []string{ComputePolicyStagingNamespace}
	twoPrincipals := good
	twoPrincipals.principals = []string{ComputePolicyNamespace, ComputePolicyStagingNamespace}
	host := good
	host.certType = ssh.HostCert
	critical := good
	critical.criticalOptions = map[string]string{"force-command": "/bin/true"}
	return map[string][]byte{
		"policy.json.sig":                   testAttestSign(t, keys.policy, ComputePolicyNamespace, document),
		"policy.json.staging.sig":           testAttestSign(t, keys.staging, ComputePolicyStagingNamespace, document),
		"policy.json.other-authority.sig":   testAttestSign(t, certified(keys.otherRelease, good), ComputePolicyNamespace, document),
		"policy.json.expired.sig":           testAttestSign(t, certified(keys.release, expired), ComputePolicyNamespace, document),
		"policy.json.not-yet.sig":           testAttestSign(t, certified(keys.release, notYet), ComputePolicyNamespace, document),
		"policy.json.long.sig":              testAttestSign(t, certified(keys.release, long), ComputePolicyNamespace, document),
		"policy.json.forever.sig":           testAttestSign(t, certified(keys.release, forever), ComputePolicyNamespace, document),
		"policy.json.staging-principal.sig": testAttestSign(t, certified(keys.release, stagingPrincipal), ComputePolicyNamespace, document),
		"policy.json.two-principals.sig":    testAttestSign(t, certified(keys.release, twoPrincipals), ComputePolicyNamespace, document),
		"policy.json.host-certificate.sig":  testAttestSign(t, certified(keys.release, host), ComputePolicyNamespace, document),
		"policy.json.critical-option.sig":   testAttestSign(t, certified(keys.release, critical), ComputePolicyNamespace, document),
		"policy.json.release-key.sig":       testAttestSign(t, keys.release, ComputePolicyNamespace, document),
		"policy.json.wrong-namespace.sig":   testAttestSign(t, keys.policy, "file", document),
		"policy.json.release-namespace.sig": testAttestSign(t, keys.policy, computeReleaseNamespace, document),
		"SHA256SUMS.sig":                    testAttestSign(t, keys.release, computeReleaseNamespace, testAttestSha256sums),
	}
}

// Every vector file but policy.json, by name: the signatures, SHA256SUMS and the release key's public line.
func testAttestVectorFiles(t testing.TB) map[string][]byte {
	t.Helper()
	files := testAttestSignatureVectors(t)
	files["SHA256SUMS"] = testAttestSha256sums
	files["release.pub"] = ssh.MarshalAuthorizedKey(newTestAttestKeys(t).release.PublicKey())
	return files
}

// A committed vector file.
func testAttestVector(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testAttestVectorDirectory, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The committed vectors are what the keys make, so a reviewer may check them with ssh-keygen -Y verify and a test
// reading one reads what this file would make. SIDECAR_WRITE_ATTEST_VECTORS=1 rewrites them.
func TestComputePolicyVectorsAreCurrent(t *testing.T) {
	files := testAttestVectorFiles(t)
	if os.Getenv(testAttestWriteVectorsEnvironment) != "" {
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(testAttestVectorDirectory, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for name, data := range files {
		committed, err := os.ReadFile(filepath.Join(testAttestVectorDirectory, name))
		if err != nil {
			t.Errorf("%s: %v (rewrite with %s=1)", name, err, testAttestWriteVectorsEnvironment)
			continue
		}
		if !bytes.Equal(committed, data) {
			t.Errorf("%s differs from what the test keys make (rewrite with %s=1)", name, testAttestWriteVectorsEnvironment)
		}
	}
}
