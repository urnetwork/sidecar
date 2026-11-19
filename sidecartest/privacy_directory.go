// §22.7's directory row at M6 (TEST-M6-01; I-20, owner decisions 170 and 181), tied to the tests that hold it
// (privacy_directory_test.go): the directory's plaintext, opened with a member's keys, holds no canary from past a
// prompt's first line, and after a revocation's erasure no stored entry that held the revoked name opens.

package sidecartest

var _ = RegisterPrivacyAssert("directory-plaintext", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestDirectoryPlaintextHoldsNoCanary"})
var _ = RegisterPrivacyAssert("directory-plaintext", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestDirectoryACanaryPastAPromptsFirstLineInAnEntryFails"})
var _ = RegisterPrivacyAssert("directory-plaintext", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestDirectoryARevokedNameStillReadableFails"})
