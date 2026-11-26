//go:build !ios_extension && !sidecar_http

// The release key's own signature (DESIGN §4.10, §2.6; REPO-M3-01): when both holders promote a release they sign its
// SHA256SUMS offline with `ssh-keygen -Y sign -n ur-release`, one SSHSIG by the release key itself, a bare key and
// never a certificate, which install.sh and ur-promote.zsh check with `ssh-keygen -Y verify`. This is that check in
// Go, for the api's model mirror, which serves a released manifest's files only once the signed sums list the
// manifest (DESIGN-COMPUTE §6.5, §14.5; CO-49; CSRV-M11-02).
//
// The keys it checks against are the ones this build pins, attest_policy_root.go's line, the compute policy's one
// root: one pin for the key ceremony to write. A source build pins none until then, so every check refuses with
// ErrComputeReleaseKeyAbsent, which is the fail-closed answer, not a fault. The framing is attest_sshsig.go's, and the
// signature formats each key type may sign with are the policy verifier's (attest_policy_verify.go).
//
// Everything here is a function of its arguments, so safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/ssh"
)

var (
	// A release signature refused; each reason below is wrapped beside it.
	ErrComputeReleaseSignatureRefused = errors.New("release signature refused")
	// No release key is pinned, so no release signature can be checked: a source build's state until the key
	// ceremony writes RELEASE-KEY.pub's line into attest_policy_root.go.
	ErrComputeReleaseKeyAbsent = errors.New("no release key exists to check it")
)

// The reasons a release signature is refused, each wrapped beside ErrComputeReleaseSignatureRefused.
var (
	// The SSHSIG was made under another namespace: a compute policy's, say, which never passes for the sums.
	errComputeReleaseNamespace = errors.New("signed under another namespace than ur-release")
	// The SSHSIG's key is a certificate: the release key signs the sums itself, and a key it certified, such as the
	// compute-policy key, never passes for it.
	errComputeReleaseCertified = errors.New("signed by a certified key, not by the release key itself")
	// The SSHSIG's key is not one the caller pins.
	errComputeReleaseKey = errors.New("signed by a key that is not a pinned release key")
	// The signature does not verify over the message, or its algorithm is one its key type may not sign with.
	errComputeReleaseSignature = errors.New("the signature does not verify")
)

// The release keys this build pins, parsed from attest_policy_root.go's line: none in a source build, whose line is
// empty until the key ceremony, and none where the line does not parse, so a check against them refuses.
func ComputeReleaseKeys() []ssh.PublicKey {
	roots, err := parseComputePolicyRoots([]byte(computePolicyReleaseKeys))
	if err != nil {
		return []ssh.PublicKey{}
	}
	return roots
}

// Nil when signature, an armored SSHSIG, signs message's exact bytes under ur-release by one of releaseKeys itself, a
// bare key with a signature format its type may sign with; otherwise an error wrapping
// ErrComputeReleaseSignatureRefused and the reason, ErrComputeReleaseKeyAbsent where releaseKeys is empty. A
// certificate in releaseKeys pins nothing. The caller bounds the sizes it reads, and nothing here repeats the bytes.
func VerifyComputeReleaseSignature(message []byte, signature []byte, releaseKeys []ssh.PublicKey) error {
	refuse := func(reason error) error {
		return fmt.Errorf("%w: %w", ErrComputeReleaseSignatureRefused, reason)
	}
	if len(releaseKeys) == 0 {
		return refuse(ErrComputeReleaseKeyAbsent)
	}
	sshsig, err := computeSshsigParse(signature)
	if err != nil {
		return refuse(errComputeSshsigFormat)
	}
	if sshsig.namespace != computeReleaseNamespace {
		return refuse(errComputeReleaseNamespace)
	}
	if _, certified := sshsig.publicKey.(*ssh.Certificate); certified {
		return refuse(errComputeReleaseCertified)
	}
	signer := sshsig.publicKey.Marshal()
	pinned := slices.ContainsFunc(releaseKeys, func(releaseKey ssh.PublicKey) bool {
		_, certified := releaseKey.(*ssh.Certificate)
		return releaseKey != nil && !certified && bytes.Equal(releaseKey.Marshal(), signer)
	})
	if !pinned {
		return refuse(errComputeReleaseKey)
	}
	if !slices.Contains(computePolicySignatureFormats[sshsig.publicKey.Type()], sshsig.signature.Format) {
		return refuse(errComputeReleaseSignature)
	}
	signed, err := computeSshsigSignedData(sshsig.namespace, sshsig.hashAlgorithm, message)
	if err != nil {
		return refuse(errComputeSshsigFormat)
	}
	if err := sshsig.publicKey.Verify(signed, sshsig.signature); err != nil {
		return refuse(errComputeReleaseSignature)
	}
	return nil
}
