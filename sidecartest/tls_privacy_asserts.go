// The tests that show the clauses of §22.7's assert block TLS-M5-25 owns (TEST-M2-10's registry): certs holds no
// certificate on a key URnetwork holds, its M5 half, beside TLS-M6-03's scope half; and tlsedge's splices are
// byte-identical, tlsedge's half, beside MAIL-M7-27's mxedge half. Each test is in this package's tests
// (tls_privacy_test.go, tls_suite_test.go).

package sidecartest

var (
	_ = RegisterPrivacyAssert("certificates", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestTlsNoCertificateRestsOnAKeyUrnetworkHolds"})
	_ = RegisterPrivacyAssert("splices", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestTlsSuitePassthroughCompletesTlsOnTheDeviceKey"})
)
