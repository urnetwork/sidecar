// M7's exit (TEST-M7-01; §23.6's M7 row; D-TEST-9, R-TEST-8, D-MAIL-9): the sweep `sidecar-gate M7` reports. Like M6's
// (gate_m6.go) it adds no mechanism, and names a case outside the convention by the same three rules:
//
//   - FS-13, FS-33, FS-39's labels case, FS-47's and FS-82's mail cases and FS-121 have no registered schedule under
//     the convention's name, and are named by the tests their owners wrote for the row, where they run: FS-13 and
//     FS-121 in this package through the receiver, FS-39 in sidecartest, FS-47's refused erasure and FS-82's mail
//     indexers in the sidecar package. FS-33 is sidecartest's two strict scenarios with TestStrictMixedArrangements
//     here, which closes the ledger's T4-05: each mix of MX selection and TLSA across customer-signed and URnetwork
//     zones, only both customer-signed carrying tls_basis.strict_custom_mx.
//   - FS-41's and FS-42's M7 steps, mail host keys and a revoked receiver's TLSA, are named where DNS and MAIL wrote
//     each, on server's rows. The step's third part, a mailbox re-formed after a site loss, has no test this sweep
//     found, so it is an item with nothing to run, which reads missing.
//   - The T3 runs the catalog names for FS-23's mailbox case, FS-47's and FS-82's mail cases and FS-121 keep the
//     convention's entry, which nothing has written, so those rows read missing.
//
// The mailbox cases of FS-76, FS-78, FS-111 and FS-112 keep the convention: they sit at the later of M7-out and M10-out.
//
// Beside the rows: §22.8's rules and FI bindings, §22.7's strict, splice, label and MTA-STS rows through the registry,
// the census harness (MAIL-M7-26), and what production owes: the census itself (D-MAIL-9), which gates burners
// (R-TEST-8) and is BS1's call, and DANE on real senders. The owner's acceptance of the SNI loss is BS1's too and is no
// test, so nothing here stands for it.

package fault

import (
	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's name for M7's exit.
const gateM7OutGate = "M7-out"

// Where M7's cases run their tests outside the convention: see the file header.
func gateM7Cases(catalog *Catalog) map[string][]*GateTest {
	caseOf := func(rowId string, caseName string) *Case {
		return gateCaseOf(catalog, rowId, caseName)
	}
	sidecarTests := func(names ...string) *GateTest {
		return &GateTest{Repo: "sidecar", Package: ".", Names: names}
	}
	cases := map[string][]*GateTest{}

	cases[caseOf("FS-13", "").String()] = []*GateTest{
		gateFaultTests("TestFs13ErasedDepositAndIndexCopiesAfterAConsumeCrash"),
	}
	cases[caseOf("FS-33", "").String()] = []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest", Names: []string{
			"TestStrictScenarioAUrnetworkZoneDirectMxIsRedirectable", "TestStrictScenarioACustomerSignedCustomMxCarriesTheClaim",
		}},
		gateFaultTests("TestStrictMixedArrangements", "TestStrictMixedArrangementsCoverEveryMix"),
	}
	cases[caseOf("FS-39", "labels").String()] = []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"TestFs39LabelsAsStatedThroughTheReceiver"}},
	}
	fs47 := caseOf("FS-47", "mail")
	cases[fs47.String()] = append([]*GateTest{sidecarTests("TestMailEraseRefused429WaitsAndResumes")}, gateConventionT3Tests(fs47)...)
	fs82 := caseOf("FS-82", "mail")
	cases[fs82.String()] = append([]*GateTest{sidecarTests(
		"TestMailIndexerAnUndesignatedTagMailDeviceRegistersNoListener", "TestMailIndexerInternetMailFromAnUndesignatedReceiverAlarms",
		"TestMailIndexerWithNoMailIndexerAnOnlineReceiverStillTakesMail", "TestMailIndexerAPersonalNetworksDesignationsWorkAtNetworkScope",
		"TestMailIndexerAMemberScopeCoversItsOwnMember", "TestMailIndexerAScopeDepositFromAnotherMembersDeviceAlarms",
		"TestMailIndexerComponentRaisesTheAlarmAsAnEvent", "TestMailIndexerComponentKeepsAnUndesignatedReceiverOff",
	)}, gateConventionT3Tests(fs82)...)
	fs121 := caseOf("FS-121", "")
	cases[fs121.String()] = gateCaseT2Named(fs121,
		"TestFs121MaximalSignaturesThroughTheReceiver", "TestFs121ArcChainsThroughTheReceiver", "TestFs121AlignmentThroughTheReceiver",
	)

	// FS-41's and FS-42's M7 steps: a receiver's key published again by its registration after a restore, and a
	// removal's effect one result under §19.10's replay
	cases[caseOf("FS-41", "m7").String()] = []*GateTest{
		gatePendingTests("./model", "TestMailHostKeyRemovalEffectIsOneResult", "TestDnsKeyRecordPublishesTheCallersKeyOnly"),
	}
	cases[caseOf("FS-42", "m7").String()] = []*GateTest{
		gatePendingTests("./model", "TestMailHostKeyRemovalEffectIsOneResult", "TestDnsKeyRecordPublishesTheCallersKeyOnly", "TestDnsTlsaRemovalEffectIsOneResult"),
	}
	return cases
}

// Every item of M7's exit: see the file header.
func gateM7OutItems(catalog *Catalog) []*GateItem {
	items := []*GateItem{
		gateRulesItem(catalog, gateM7OutGate),
		gateInvariantsItem(gateM7OutGate),
	}
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM7OutGate)...)
	if 0 < len(gateStoreClockCases(catalog, gateM7OutGate)) {
		items = append(items, gateStoreClockItem(catalog, gateM7OutGate))
	}
	items = append(items,
		&GateItem{
			Item: "the ledger's T4-05 closed (HANDOFF §10; TEST-M7-01): FS-33 on R1b's mixed arrangements, each mix of MX selection and TLSA across customer-signed and URnetwork zones, the strict claim carried by both customer-signed alone, and every mix covered",
			Tests: []*GateTest{
				gateFaultTests("TestStrictMixedArrangements", "TestStrictMixedArrangementsCoverEveryMix"),
			},
		},
		&GateItem{
			Item: "FS-41's M7 step, a mailbox re-formed after a site loss (§22.8's FS-41, §23.6's M7 row): no test this sweep found shows it, as M3's vault re-form tests show a vault's",
		},
		&GateItem{
			Item: "the census run's harness (MAIL-M7-26; D-MAIL-9): scripted senders counted, a fallback counted once, a list it cannot judge refused, a scrape read, and the report senders listed with a missing one named",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/mailcensus", Names: []string{
					"TestCensusOnScriptedSenders", "TestCensusCountsAFallbackOnce", "TestCensusRefusesAListItCannotJudge", "TestCensusReadsAScrape",
					"TestCensusListsTheReportSenders", "TestCensusNamesAMissingReportSender",
				}},
			},
		},
		&GateItem{
			Item:     "D-MAIL-9's census run, with §14's outbound probe: the census gates burners (R-TEST-8) and is BS1's, open until the owner calls it",
			External: "production: the production edges",
		},
		&GateItem{
			Item:     "DANE on real senders: strict MX against senders that validate TLSA (§23.6's M7 row)",
			External: "production: real sending domains, which no local run reaches",
		},
	)
	return items
}

var gateM7Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M7",
	Cases: gateM7Cases(DefaultCatalog()),
	Items: gateM7OutItems(DefaultCatalog()),
})
