//go:build sidecar_testhooks && !ios_extension && !sidecar_http

// The sidecar_testhooks seam for sidecartest's compute fakes (CTEST-M11-02's FakeComputePolicy, DESIGN-COMPUTE §18): a
// verifier that pins test release keys in place of RELEASE-KEY.pub's, and a store whose release's copy a test gives.
// Only the sidecar_testhooks build has it (§22.4), and make check fails a release leg built with that tag, so no
// shipped build trusts a test key.

package sidecar

import (
	"golang.org/x/crypto/ssh"
)

// A verifier pinning releaseKeys, for a production build's namespace or, with staging, a staging build's.
func NewComputePolicyVerifierForTest(settings *AttestSettings, releaseKeys []ssh.PublicKey, staging bool) *ComputePolicyVerifier {
	namespace := ComputePolicyNamespace
	if staging {
		namespace = ComputePolicyStagingNamespace
	}
	return newComputePolicyVerifier(settings, releaseKeys, namespace, staging)
}

// Gives the store these args build the release's copy document and signature in place of the embedded one; nil and
// nil is a build that carries none.
func (self *ComputePolicyStoreArgs) SetReleaseCopyForTest(document []byte, signature []byte) {
	self.releaseDocument = document
	self.releaseSignature = signature
	self.releaseGiven = true
}
