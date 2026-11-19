package sidecartest_test

// §22.7's revocation suite's member form on T2 (TEST-M6-01; R-TEST-4, D-TEST-6): X a member, removed by an Admin's
// MemberRevoke and by the scim_signer's as SCIM's active=false asks, with every check this binary registers: TEAM's
// (fault.TeamMemberRevocationCheck, the log's clause, each way with its own signer), and the keys and acl checks
// sidecartest/scenarios composes (revocation_member.go). The keys check runs with evs's gate off, so what refuses X is
// the members' own rotation: under sidecar_testhooks it judges both of X's devices' held keys; without them the gate
// cannot be switched, and it reads open, never passed. Owner decision 83's clause, a removed member's tagged agents
// keeping their tags' grants with autogroup:sponsor resolving to autogroup:admin until a SponsorSet, is ACL's schedule
// run as a check. The mutant is a signer that writes on under the generation X holds.

import (
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/fault"
	"github.com/urnetwork/sidecar/sidecartest/scenarios"
)

// The result of checkId in way, failing t when the report holds none.
func revocationMemberResult(t *testing.T, report *sidecartest.RevocationReport, way sidecartest.RevocationWay, checkId string) *sidecartest.RevocationResult {
	t.Helper()
	results := report.Of(way)
	index := slices.IndexFunc(results, func(result *sidecartest.RevocationResult) bool { return result.CheckId == checkId })
	if index < 0 {
		t.Fatalf("%s: %s did not run", way, checkId)
	}
	return results[index]
}

// The member form, whole: both ways named and none failing. TEAM's check judges each way; the keys check runs gate
// off in each and judges under the hooks; ACL's two schedules judge an Admin's removal and read open under SCIM's.
func TestRevocationSuiteMemberFormWhole(t *testing.T) {
	report := sidecartest.RunRevocationSuite(t, sidecartest.RevocationFormMember, nil)
	if 0 < len(report.Missing) {
		t.Fatalf("ways no check names: %v", report.Missing)
	}
	ways := sidecartest.RevocationFormMember.Ways()
	if !slices.Equal(ways, []sidecartest.RevocationWay{sidecartest.RevocationMemberRemove, sidecartest.RevocationScimInactive}) {
		t.Fatalf("the member form's ways: %v", ways)
	}
	for _, way := range ways {
		if team := revocationMemberResult(t, report, way, fault.TeamMemberRevocationCheck.Id); team.Err != nil || team.Open != "" {
			t.Errorf("TEAM's check did not judge: %s", team)
		}
		keys := revocationMemberResult(t, report, way, scenarios.RevocationMemberKeys.Id)
		switch {
		case !keys.GateOff:
			t.Errorf("the keys check ran with the gate on: %s", keys)
		case sidecartest.HooksLinked && (keys.Err != nil || keys.Open != ""):
			t.Errorf("the keys check did not judge under the hooks: %s", keys)
		case !sidecartest.HooksLinked && (keys.Err != nil || keys.Open == ""):
			t.Errorf("the keys check did not read open without the hooks, which hold none of X's keys and switch no gate: %s", keys)
		}
		for _, check := range []*sidecartest.RevocationCheck{scenarios.RevocationMemberTaggedAgents, scenarios.RevocationMemberRightsDropped} {
			acl := revocationMemberResult(t, report, way, check.Id)
			switch {
			case acl.Err != nil:
				// RunRevocationSuite failed t with it
			case way == sidecartest.RevocationMemberRemove && acl.Open != "":
				t.Errorf("ACL's check did not judge an Admin's removal: %s", acl)
			case way == sidecartest.RevocationScimInactive && acl.Open == "":
				t.Errorf("ACL's check, which takes no signer, passed SCIM's way: %s", acl)
			}
		}
	}
}

// A signer that writes on under the generation X's devices hold: the suite fails it in both ways. It needs the hooks,
// as the gate's switch does.
func TestRevocationSuiteMemberFormFailsARevokedMemberStillReading(t *testing.T) {
	settings := &sidecartest.RevocationSuiteSettings{Checks: []*sidecartest.RevocationCheck{scenarios.RevocationMemberKeysCheck(true)}}
	report := (&sidecartest.RevocationSuite{Form: sidecartest.RevocationFormMember}).Run(t, settings)
	if len(report.Results) != len(sidecartest.RevocationFormMember.Ways()) {
		t.Fatalf("the mutant ran in %d ways: %s", len(report.Results), report)
	}
	for _, result := range report.Results {
		switch {
		case !sidecartest.HooksLinked:
			if result.Open == "" || result.Err != nil {
				t.Errorf("%s: without the hooks the mutant did not read open: %s", result.Way, result)
			}
		case result.Err == nil || !strings.Contains(result.Err.Error(), "which X holds"):
			t.Errorf("%s: not failed for writing under a generation X holds: %s", result.Way, result)
		}
	}
	if sidecartest.HooksLinked && !report.Failed() {
		t.Fatalf("the mutant passed: %s", report)
	}
}

// A form whose only check names one way is missing the other: an Admin's removal checked says nothing of SCIM's.
func TestRevocationSuiteMemberFormNeedsBothWays(t *testing.T) {
	only := &sidecartest.RevocationCheck{
		Id: "test/member-remove-only", Area: "TEST", Ways: []sidecartest.RevocationWay{sidecartest.RevocationMemberRemove},
		Run: func(run *sidecartest.RevocationRun) (string, error) { return "", nil },
	}
	report := (&sidecartest.RevocationSuite{Form: sidecartest.RevocationFormMember}).Run(t, &sidecartest.RevocationSuiteSettings{Checks: []*sidecartest.RevocationCheck{only}})
	if !report.Failed() || !slices.Equal(report.Missing, []sidecartest.RevocationWay{sidecartest.RevocationScimInactive}) {
		t.Fatalf("a form checked in one way: %s", report)
	}
}
