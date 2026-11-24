//go:build !ios_extension && !sidecar_http && !sidecar_compute_staging

// A production build's pin (DESIGN-COMPUTE §5.4, D-ATTEST-8): the production namespace alone, so a policy the staging
// key signed is refused here, and the release's copy is the production policy. A staging or CI build is built with
// the sidecar_compute_staging tag, which takes attest_policy_pin_staging.go in place of this file.

package sidecar

// The namespace every policy and ticket this build verifies was signed under.
const computePolicyBuildNamespace = ComputePolicyNamespace

// Whether this is a staging or CI build, whose policy expires after 7 days whatever it says and whose apps show the
// staging banner.
const computePolicyStagingBuild = false

// The release's copy of the policy in attest_policy_release/, and its detached signature.
const (
	computePolicyReleaseDocumentName  = "compute-policy.json"
	computePolicyReleaseSignatureName = "compute-policy.json.sig"
)
