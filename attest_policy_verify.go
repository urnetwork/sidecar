//go:build !ios_extension && !sidecar_http

// The compute policy's verifier (DESIGN-COMPUTE §5.4, R-ATTEST-3, D-ATTEST-2, D-ATTEST-8, D-ATTEST-9, IC-9), to the
// reading compute-plan-policy-signature-format's answer recorded (QD-1256): one SSHSIG over the exact bytes, detached
// as <version>.json.sig, under this build's namespace, by a key whose OpenSSH certificate the pinned release key
// signed. A policy verifies only when every one of these holds, checked in this order, each refusal its own error
// wrapped in ErrComputePolicyRefused:
//
//	sizes      the document within PolicyMaxByteCount and the signature within SignatureMaxByteCount
//	root       this build pins a release key; a source build pins none until the key ceremony, so it verifies nothing
//	framing    the signature is one armored SSHSIG (attest_sshsig.go)
//	namespace  the SSHSIG's is this build's alone: ur-compute-policy in production, ur-compute-policy-staging in a
//	           staging or CI build, so a staging line never reaches a user and a release signature (ur-release) never
//	           passes for a policy
//	certified  the SSHSIG's key is an OpenSSH user certificate, never a bare key, so the release key itself, signing
//	           anything, never passes for the compute-policy key, nor the reverse
//	authority  the certificate's signer is a pinned release key, with an algorithm this file takes
//	principal  the certificate names this build's namespace as its one principal, so a key certified for staging
//	           signs no production policy, nor the reverse
//	validity   valid now, and for at most CertificateMaxValidity from its start: never forever
//	options    no critical option
//	signature  the certified key's signature over the SSHSIG's signed data for the document's bytes, with a key and
//	           algorithm this file takes: Ed25519, ECDSA on P-256, P-384 or P-521, their FIDO forms with user presence,
//	           or RSA of RsaMinBitCount or more with SHA-2
//	format     the document parses strictly as this build's format (attest_policy.go)
//
// "Two of four holders sign" is two-person custody of the one certified key, a ceremony, as the release key's is: the
// device checks one signature (QD-1256). The same checks verify a freshness ticket's signature (ATTEST-M12-01), under
// the same namespace; the ticket's own strict parse keeps it from passing for a policy.
//
// Safe for concurrent use: a verifier is fixed once built.

package sidecar

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// The reasons a signature is refused, each wrapped in ErrComputePolicyRefused.
var (
	// The document or signature past its size bound.
	errComputePolicyTooLarge = errors.New("larger than this build takes")
	// This build pins no release key.
	errComputePolicyNoRoot = errors.New("this build pins no release key")
	// The signature is not an SSHSIG.
	errComputePolicySignatureFormat = errors.New("the signature is not an SSHSIG")
	// The SSHSIG's namespace is not this build's.
	errComputePolicyNamespace = errors.New("signed under another namespace")
	// The SSHSIG's key is a bare key, not a certificate.
	errComputePolicyNotCertified = errors.New("signed by a key no certificate names")
	// The certificate's signer is not a pinned release key, or signed with an algorithm refused.
	errComputePolicyAuthority = errors.New("certified by a key this build does not pin")
	// The certificate names another principal, or more than one.
	errComputePolicyPrincipal = errors.New("certified for another namespace")
	// The certificate is not valid now, is valid too long, or is no user certificate.
	errComputePolicyValidity = errors.New("its certificate is not valid now or for at most its bound")
	// The certificate carries a critical option.
	errComputePolicyCriticalOption = errors.New("its certificate carries a critical option")
	// The signature does not verify under the certified key, or its key or algorithm is refused.
	errComputePolicySignature = errors.New("the signature does not verify")
)

// The signature formats each key type may sign with, as §5.4's holders' tokens and the release key make them: no
// SHA-1 RSA, no DSA.
var computePolicySignatureFormats = map[string][]string{
	ssh.KeyAlgoED25519:    {ssh.KeyAlgoED25519},
	ssh.KeyAlgoSKED25519:  {ssh.KeyAlgoSKED25519},
	ssh.KeyAlgoECDSA256:   {ssh.KeyAlgoECDSA256},
	ssh.KeyAlgoECDSA384:   {ssh.KeyAlgoECDSA384},
	ssh.KeyAlgoECDSA521:   {ssh.KeyAlgoECDSA521},
	ssh.KeyAlgoSKECDSA256: {ssh.KeyAlgoSKECDSA256},
	ssh.KeyAlgoRSA:        {ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512},
}

// Verifies policies and tickets against this build's pins: the release keys and the one namespace.
type ComputePolicyVerifier struct {
	settings *AttestSettings
	// The release keys a certificate's signer must be, parsed.
	roots []ssh.PublicKey
	// The one namespace this build verifies.
	namespace string
	// Whether this is a staging or CI build.
	staging bool
}

// This build's verifier: the release key attest_policy_root.go pins, empty in a source build, and this build's
// namespace. A pinned line that does not parse pins nothing, so every policy is refused.
func NewComputePolicyVerifier(settings *AttestSettings) *ComputePolicyVerifier {
	roots, err := parseComputePolicyRoots([]byte(computePolicyReleaseKeys))
	if err != nil {
		roots = []ssh.PublicKey{}
	}
	return newComputePolicyVerifier(settings, roots, computePolicyBuildNamespace, computePolicyStagingBuild)
}

// A verifier over roots and namespace: the seam tests and sidecartest's fakes use to stand in test keys and either
// build's namespace (attest_policy_testhooks.go).
func newComputePolicyVerifier(settings *AttestSettings, roots []ssh.PublicKey, namespace string, staging bool) *ComputePolicyVerifier {
	return &ComputePolicyVerifier{
		settings:  settings,
		roots:     slices.Clone(roots),
		namespace: namespace,
		staging:   staging,
	}
}

// The keys of authorized_keys lines, blank lines and # comments skipped. A certificate is never a root.
func parseComputePolicyRoots(text []byte) ([]ssh.PublicKey, error) {
	roots := []ssh.PublicKey{}
	for 0 < len(bytes.TrimSpace(text)) {
		publicKey, _, _, rest, err := ssh.ParseAuthorizedKey(text)
		if err != nil {
			return nil, fmt.Errorf("compute policy roots: %w", err)
		}
		if _, ok := publicKey.(*ssh.Certificate); ok {
			return nil, errors.New("compute policy roots: a certificate is not a root")
		}
		roots = append(roots, publicKey)
		text = rest
	}
	return roots, nil
}

// The namespace this verifier takes.
func (self *ComputePolicyVerifier) Namespace() string {
	return self.namespace
}

// Whether it verifies for a staging or CI build.
func (self *ComputePolicyVerifier) Staging() bool {
	return self.staging
}

// The policy document holds, once its detached armored signature verifies at now and it parses strictly; else an
// error wrapping ErrComputePolicyRefused and the reason's own error, which never repeats the bytes. now is the device's
// clock as the caller reads it; the store and the gate never pass one earlier than the newest current ticket's start.
func (self *ComputePolicyVerifier) Verify(document []byte, signature []byte, now time.Time) (*ComputePolicy, error) {
	if self.settings.PolicyMaxByteCount < len(document) {
		return nil, fmt.Errorf("%w: the document is %w", ErrComputePolicyRefused, errComputePolicyTooLarge)
	}
	signer, err := self.verifySignature(document, signature, now)
	if err != nil {
		return nil, err
	}
	policy, err := parseComputePolicy(document, self.settings)
	if err != nil {
		return nil, err
	}
	policy.signature = bytes.Clone(signature)
	policy.signer = *signer
	return policy, nil
}

// The signer whose certified key signed message under this build's namespace, checked at now, or why not.
func (self *ComputePolicyVerifier) verifySignature(message []byte, signature []byte, now time.Time) (*ComputePolicySigner, error) {
	refuse := func(reason error) error {
		return fmt.Errorf("%w: %w", ErrComputePolicyRefused, reason)
	}
	if self.settings.SignatureMaxByteCount < len(signature) {
		return nil, fmt.Errorf("%w: the signature is %w", ErrComputePolicyRefused, errComputePolicyTooLarge)
	}
	if len(self.roots) == 0 {
		return nil, refuse(errComputePolicyNoRoot)
	}
	sshsig, err := computeSshsigParse(signature)
	if err != nil {
		return nil, refuse(errComputePolicySignatureFormat)
	}
	if sshsig.namespace != self.namespace {
		return nil, refuse(errComputePolicyNamespace)
	}
	certificate, ok := sshsig.publicKey.(*ssh.Certificate)
	if !ok {
		return nil, refuse(errComputePolicyNotCertified)
	}
	if err := self.checkCertificate(certificate, now); err != nil {
		return nil, refuse(err)
	}
	if err := self.checkKey(certificate.Key, sshsig.signature); err != nil {
		return nil, refuse(err)
	}
	signed, err := computeSshsigSignedData(sshsig.namespace, sshsig.hashAlgorithm, message)
	if err != nil {
		return nil, refuse(errComputePolicySignatureFormat)
	}
	// x/crypto's FIDO keys refuse a signature without the user-presence flag here
	if err := certificate.Key.Verify(signed, sshsig.signature); err != nil {
		return nil, refuse(errComputePolicySignature)
	}
	return &ComputePolicySigner{
		KeyId:       certificate.KeyId,
		Serial:      certificate.Serial,
		Fingerprint: ssh.FingerprintSHA256(certificate.Key),
		Namespace:   sshsig.namespace,
	}, nil
}

// The certificate's own rules: a user certificate, by a pinned root with an algorithm taken, naming this namespace
// alone, valid now and for at most the bound, with no critical option, its signature verifying.
func (self *ComputePolicyVerifier) checkCertificate(certificate *ssh.Certificate, now time.Time) error {
	if certificate.CertType != ssh.UserCert {
		return errComputePolicyValidity
	}
	authority := certificate.SignatureKey.Marshal()
	pinned := slices.ContainsFunc(self.roots, func(root ssh.PublicKey) bool {
		return bytes.Equal(root.Marshal(), authority)
	})
	if !pinned || certificate.Signature == nil ||
		!slices.Contains(computePolicySignatureFormats[certificate.SignatureKey.Type()], certificate.Signature.Format) {
		return errComputePolicyAuthority
	}
	if !slices.Equal(certificate.ValidPrincipals, []string{self.namespace}) {
		return errComputePolicyPrincipal
	}
	if len(certificate.CriticalOptions) != 0 {
		return errComputePolicyCriticalOption
	}
	maxSeconds := self.settings.CertificateMaxValidity / time.Second
	if certificate.ValidBefore == ssh.CertTimeInfinity || certificate.ValidBefore <= certificate.ValidAfter ||
		maxSeconds <= 0 || uint64(maxSeconds) < certificate.ValidBefore-certificate.ValidAfter {
		return errComputePolicyValidity
	}
	unixNow := now.Unix()
	if unixNow < 0 || uint64(unixNow) < certificate.ValidAfter || certificate.ValidBefore <= uint64(unixNow) {
		return errComputePolicyValidity
	}
	// the principal, the window and the critical options again, and the authority's signature, as OpenSSH checks them
	checker := &ssh.CertChecker{Clock: func() time.Time { return now }}
	if err := checker.CheckCert(self.namespace, certificate); err != nil {
		return errComputePolicyAuthority
	}
	return nil
}

// The certified key's type and its signature's algorithm, one this file takes, and an RSA key's size.
func (self *ComputePolicyVerifier) checkKey(publicKey ssh.PublicKey, signature *ssh.Signature) error {
	if !slices.Contains(computePolicySignatureFormats[publicKey.Type()], signature.Format) {
		return errComputePolicySignature
	}
	if publicKey.Type() == ssh.KeyAlgoRSA {
		cryptoKey, ok := publicKey.(ssh.CryptoPublicKey)
		if !ok {
			return errComputePolicySignature
		}
		rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() < self.settings.RsaMinBitCount {
			return errComputePolicySignature
		}
	}
	return nil
}
