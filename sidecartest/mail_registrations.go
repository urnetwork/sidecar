// What MAIL-M7-27 composes for M7's exit, registered where a gate reads it (§22.7, §23.6): S7's clauses on T2 and T3,
// and the assert block's mail clauses. A part no test is registered to reads missing at its gate, never passing: S7's
// receive-side clauses on T3 (reception-time DNS, tampered evidence and a cut check through a receiver on server's
// stores), and T6, whose run is the main test environment's.
//
// And what MAIL-M8-10 composes for BS1's receive-only launch: S10's receive-only half on T2. Its replying half is
// MAIL-M9-06's, and S10 on T3 reads missing until a world composes the receiver and mailcfg on server's stores.

package sidecartest

const (
	mailRegistrationsSidecar        = "github.com/urnetwork/sidecar/sidecartest"
	mailRegistrationsRoot           = "github.com/urnetwork/sidecar"
	mailRegistrationsServerMxedge   = "github.com/urnetwork/server/cli/mxedge"
	mailRegistrationsServerMxHost   = "github.com/urnetwork/server/mxedgehost"
	mailRegistrationsTestHooks      = "sidecar_testhooks"
	mailRegistrationsSidecarPending = "sidecar_pending"
)

var (
	// S7 on T2: the composed flow (mail_s7_test.go), and its SNI-less abuse@<root> part, MAIL-M5-04's
	// (mail_platform_scenario_test.go)
	_ = registerMailS7(ScenarioTierT2, &ScenarioTest{Repo: "sidecar", Package: mailRegistrationsSidecar, Name: "TestScenarioS7ReceiveMail", Tags: mailRegistrationsTestHooks},
		"plaintext-530", "unroutable-temporary-failure", "reception-time-dns-kept", "tampered-evidence-fails", "bound-cut-labeled-from-what-was-verified")
	_ = registerMailS7(ScenarioTierT2, &ScenarioTest{Repo: "sidecar", Package: mailRegistrationsSidecar, Name: "TestPlatformScenarioSniLessAbuseMailReachesTheIntake"},
		"sni-less-abuse-reaches-the-platform-listener")
	// S7 on T3: the router's clauses on server's host and the private stack (server/cli/mxedge), and the platform block's
	// run on the stores (server/mxedgehost)
	_ = registerMailS7(ScenarioTierT3, &ScenarioTest{Repo: "server", Package: mailRegistrationsServerMxedge, Name: "TestT3S7RouterRefusesHoldsNothingAndRecordsNoAddress", Tags: mailRegistrationsSidecarPending},
		"plaintext-530", "unroutable-temporary-failure")
	_ = registerMailS7(ScenarioTierT3, &ScenarioTest{Repo: "server", Package: mailRegistrationsServerMxHost, Name: "TestRunHostOnThePrivateStores"},
		"sni-less-abuse-reaches-the-platform-listener")

	// S10's receive-only half on T2 (mail_s10_test.go): a burned label's 550 with the zone unchanged, and a receive-only
	// burner's absent child, through MailClient's calls that the bound API wraps
	_ = registerMailScenario("S10", ScenarioTierT2, &ScenarioTest{Repo: "sidecar", Package: mailRegistrationsSidecar, Name: "TestScenarioS10ReceiveOnlyBurner", Tags: mailRegistrationsTestHooks},
		"burned-label-550-no-dns-change", "receive-only-burner-creates-no-child")

	// strict mode (FS-33; MAIL-M7-24's mechanism): refused URnetwork-zone splices and the claim only from a sealed
	// strict_chain, on MxWorld's signed zones and through the receiver's admission and session
	_ = RegisterPrivacyAssert("strict-mode", &PrivacyAssertTest{Repo: "sidecar", Package: mailRegistrationsSidecar, Name: "TestStrictScenarioAUrnetworkZoneDirectMxIsRedirectable"})
	_ = RegisterPrivacyAssert("strict-mode", &PrivacyAssertTest{Repo: "sidecar", Package: mailRegistrationsSidecar, Name: "TestStrictScenarioACustomerSignedCustomMxCarriesTheClaim"})
	_ = RegisterPrivacyAssert("strict-mode", &PrivacyAssertTest{Repo: "sidecar", Package: mailRegistrationsRoot, Name: "TestMailStrictRefusesASpliceBeforeAnySmtpByte"})
	_ = RegisterPrivacyAssert("strict-mode", &PrivacyAssertTest{Repo: "sidecar", Package: mailRegistrationsRoot, Name: "TestMailStrictSealsStrictChainOnlyForACustomHostSplice"})
	// mxedge's half of the splice clause: every byte value both ways through the router's splice, as each end saw it
	_ = RegisterPrivacyAssert("splices", &PrivacyAssertTest{Repo: "sidecar", Package: mailRegistrationsSidecar, Name: "TestMailSpliceIsByteIdentical", Tags: mailRegistrationsTestHooks})
	// labels from sealed evidence through the composed path, beside MAIL-M7-10's decisions
	_ = RegisterPrivacyAssert("mail-labels", &PrivacyAssertTest{Repo: "sidecar", Package: mailRegistrationsSidecar, Name: "TestScenarioS7ReceiveMail", Tags: mailRegistrationsTestHooks})
	_ = RegisterPrivacyAssert("mail-labels", &PrivacyAssertTest{Repo: "sidecar", Package: mailRegistrationsSidecar, Name: "TestFs39LabelsAsStatedThroughTheReceiver", Tags: mailRegistrationsTestHooks})
)

// Registers test to each of S7's clauses on tier.
func registerMailS7(tier string, test *ScenarioTest, clauses ...string) bool {
	return registerMailScenario("S7", tier, test, clauses...)
}

// Registers test to each of scenarioId's clauses on tier.
func registerMailScenario(scenarioId string, tier string, test *ScenarioTest, clauses ...string) bool {
	for _, clause := range clauses {
		RegisterScenario(scenarioId, clause, tier, test)
	}
	return true
}
