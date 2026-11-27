//go:build !ios_extension && !sidecar_http && sidecar_compute_staging

// A staging or CI build's pin (DESIGN-COMPUTE §5.4, D-ATTEST-8): the staging namespace alone, so this build verifies
// only what the staging key signed, a gated line's first home (§4.7, §19.2), and never the production policy. No
// release is built with this tag; make check's release legs set no tag that takes this file.

package sidecar

// The namespace every policy and ticket this build verifies was signed under.
const computePolicyBuildNamespace = ComputePolicyStagingNamespace

// Whether this is a staging or CI build, whose policy expires after 7 days whatever it says and whose apps show the
// staging banner.
const computePolicyStagingBuild = true

// The release's copy of the staging policy in attest_policy_release/, and its detached signature.
const (
	computePolicyReleaseDocumentName  = computePolicyStagingCopyName
	computePolicyReleaseSignatureName = computePolicyStagingCopyName + computePolicySignatureSuffix
)
