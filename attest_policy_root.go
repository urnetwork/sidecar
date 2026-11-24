//go:build !ios_extension && !sidecar_http

// The compute policy's one root (DESIGN-COMPUTE §5.4, D-ATTEST-9, Q-ATTEST-4): devices pin the release key, the
// offline two-person Ed25519 key that signs SHA256SUMS under ur-release (DESIGN §2.6, §4.10), and nothing else. The
// release key certifies the compute-policy key for ur-compute-policy alone and the staging key for
// ur-compute-policy-staging alone, each for at most a year; a policy or ticket verifies only under a certified key
// whose certificate the pinned key signed (compute-plan-policy-signature-format, QD-1256).
//
// The key is written here once it exists, as RELEASE-KEY.pub publishes it, by the key ceremony (External). Until then
// the line is empty, so a build from this tree pins no root and verifies no policy: every remote operation §5.4's
// gate covers refuses, which is the fail-closed answer, not a fault. Tests pin test keys through the verifier's
// unexported constructor, and sidecartest's fakes through the sidecar_testhooks seam (attest_policy_testhooks.go).

package sidecar

// The release key as RELEASE-KEY.pub writes it, one authorized_keys line, or more than one only while the release
// key rotates. A cryptographic constant, set once by the key ceremony; empty pins nothing.
const computePolicyReleaseKeys = ""

// §5.4's namespaces, identifiers. A build pins one of the two policy namespaces alone (attest_policy_pin.go,
// attest_policy_pin_staging.go), so no staging line reaches a user and no production policy runs a staging build.
const (
	// The production policy's and its tickets', signed by the compute-policy key.
	ComputePolicyNamespace = "ur-compute-policy"
	// The staging policy's and its tickets', signed by the staging key.
	ComputePolicyStagingNamespace = "ur-compute-policy-staging"
	// The release key's own, over SHA256SUMS (DESIGN §4.10), which never passes for a policy.
	computeReleaseNamespace = "ur-release"
)
