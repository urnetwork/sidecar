//go:build !ios_extension && !sidecar_http

// The release's copy of the compute policy (DESIGN-COMPUTE §5.4's Distribution): each `ur` release carries the policy
// current at its build, embedded from attest_policy_release/, which ATTEST-M12-02's publish step writes before a
// release. A source build holds no copy there, only its README. The copy is verified as any policy is, under this
// build's pins, and a device never takes a policy older than it (ComputePolicyStore).

package sidecar

import (
	"embed"
	"errors"
	"io/fs"
)

// attest_policy_release/ as the build found it.
//
//go:embed attest_policy_release
var computePolicyReleaseFiles embed.FS

// The directory the copy is embedded from.
const computePolicyReleaseDirectory = "attest_policy_release"

// The release's copy, its document and signature, or nil and nil where this build carries none. One without the other
// is an error: a release whose publish step wrote half a copy.
func computePolicyReleaseCopy() (document []byte, signature []byte, err error) {
	return computePolicyReleaseCopyFrom(computePolicyReleaseFiles, computePolicyReleaseDirectory)
}

// As computePolicyReleaseCopy, from files' directory, the seam tests read another tree through.
func computePolicyReleaseCopyFrom(files fs.FS, directory string) (document []byte, signature []byte, err error) {
	document, documentErr := fs.ReadFile(files, directory+"/"+computePolicyReleaseDocumentName)
	signature, signatureErr := fs.ReadFile(files, directory+"/"+computePolicyReleaseSignatureName)
	documentAbsent := errors.Is(documentErr, fs.ErrNotExist)
	signatureAbsent := errors.Is(signatureErr, fs.ErrNotExist)
	switch {
	case documentAbsent && signatureAbsent:
		return nil, nil, nil
	case documentErr != nil || signatureErr != nil:
		return nil, nil, errors.New("the release's copy of the compute policy is incomplete")
	}
	return document, signature, nil
}
