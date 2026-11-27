package sidecar

// CACL-M12-03: the compute block's parse (DESIGN-COMPUTE §16.4): each key read against its schema with §16.5's defaults
// left to the view, an unknown or repeated key and a value of the wrong type refused, USD read exactly into nano-USD,
// history's share bounded, and the block-alone record a network with no document keeps. Pure, on every leg.

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A block naming every key, as a Team's admin might write it.
const testComputeBlockFull = `{"compute": {
  // what remote inference may use
  "assurance_floor": "AP",
  "providers": ["engy", "chutes"],
  "enclave_assurance_floor": "A1",
  "budgets": [
    {"subjects": ["autogroup:tagged"], "per": "subject", "day_usd": 5, "month_usd": 50},
    {"subjects": ["group:interns"], "per": "member", "month_usd": 100.5},
  ],
  "enclave_shapes": ["cpu-4", "cpu-2"],
  "search": {"enabled": true, "modes": ["fast", "turbo"], "day_max": 2000},
  "fetch": {"enabled": true, "egress": "exits", "exit": "tag:exit"},
  "calendar": {"enabled": false, "egress": "direct"},
  "connect": {"enabled": true, "services": ["google-calendar"], "generic": false, "custom": true, "egress": "auto"},
  "support": {"egress": "persons", "agents": true, "logs": false},
  "approvals": {"auto": ["fetch_unlisted_url", "service_write"]},
  "disclosures": {"inference:engy": "c3RhdGVtZW50"},
  "history": {"member_share": 0.25},
}}`

// The block of source, which must parse.
func testComputeBlockParsed(t *testing.T, source string) *AclComputeBlock {
	t.Helper()
	policy, err := ParseAclPolicy([]byte(source))
	if err != nil {
		t.Fatalf("%s: %v", source, err)
	}
	return policy.Compute
}

// An empty block parses to nothing set, so every key reads its default; a full one to each value as written.
func TestComputeBlockParseDefaults(t *testing.T) {
	if policy, err := ParseAclPolicy([]byte(`{"grants": []}`)); err != nil || policy.Compute != nil {
		t.Fatalf("a document with no block: %v, %v", policy, err)
	}
	empty := testComputeBlockParsed(t, `{"compute": {}}`)
	if empty == nil || empty.AssuranceFloor != 0 || empty.Providers != nil || empty.EnclaveAssuranceFloor != 0 ||
		empty.Budgets != nil || empty.EnclaveShapes != nil || empty.Search != nil || empty.Fetch != nil ||
		empty.Calendar != nil || empty.Connect != nil || empty.Support != nil || empty.Approvals != nil ||
		empty.Disclosures != nil || empty.History != nil {
		t.Errorf("an empty block: %+v", empty)
	}

	block := testComputeBlockParsed(t, testComputeBlockFull)
	if block.AssuranceFloor != protocol.ComputeAssurance_COMPUTE_ASSURANCE_AP || !slices.Equal(block.Providers, []string{"engy", "chutes"}) ||
		block.EnclaveAssuranceFloor != protocol.ComputeAssurance_COMPUTE_ASSURANCE_A1 ||
		!slices.Equal(block.EnclaveShapes, []string{"cpu-4", "cpu-2"}) {
		t.Errorf("the floors and lists: %+v", block)
	}
	if len(block.Budgets) != 2 || block.Budgets[0].Per != AclComputeBudgetPerSubject || block.Budgets[0].DayNanoUsd != 5_000_000_000 ||
		block.Budgets[0].MonthNanoUsd != 50_000_000_000 || block.Budgets[1].Per != AclComputeBudgetPerMember ||
		block.Budgets[1].DayNanoUsd != 0 || block.Budgets[1].MonthNanoUsd != 100_500_000_000 ||
		block.Budgets[1].Subjects[0].String() != "group:interns" {
		t.Errorf("the budgets: %+v", block.Budgets)
	}
	if !*block.Search.Enabled || !slices.Equal(block.Search.Modes, []string{"fast", "turbo"}) || block.Search.DayMax != 2000 {
		t.Errorf("search: %+v", block.Search)
	}
	if block.Fetch.Egress != AclComputeEgressExits || block.Fetch.Exit.String() != "tag:exit" ||
		*block.Calendar.Enabled || block.Calendar.Egress != AclComputeEgressDirect {
		t.Errorf("fetch and calendar: %+v, %+v", block.Fetch, block.Calendar)
	}
	if !slices.Equal(block.Connect.Services, []string{"google-calendar"}) || *block.Connect.Generic || !*block.Connect.Custom ||
		block.Connect.Egress != AclComputeEgressAuto {
		t.Errorf("connect: %+v", block.Connect)
	}
	if block.Support.Egress != "persons" || !*block.Support.Agents || *block.Support.Logs {
		t.Errorf("support: %+v", block.Support)
	}
	if !slices.Equal(block.Approvals.Auto, []SidecarActionKind{SidecarActionFetchUnlistedUrl, SidecarActionServiceWrite}) {
		t.Errorf("approvals: %+v", block.Approvals)
	}
	if !slices.Equal(block.Disclosures, []AclComputeDisclosure{{Id: "inference:engy", Statement: "c3RhdGVtZW50"}}) {
		t.Errorf("disclosures: %+v", block.Disclosures)
	}
	if block.History.MemberShareAuto || block.History.MemberSharePpm != 250_000 {
		t.Errorf("history: %+v", block.History)
	}
	if subjects := block.selectors(); len(subjects) != 3 || subjects[2].String() != "tag:exit" {
		t.Errorf("the block's selectors: %v", subjects)
	}
	// approvals may name none, which sends every approval to a person
	if none := testComputeBlockParsed(t, `{"compute": {"approvals": {"auto": []}}}`); none.Approvals == nil || len(none.Approvals.Auto) != 0 {
		t.Errorf("approvals naming none: %+v", none.Approvals)
	}
}

// What the schema has no place for, a key given twice and a value it cannot take are refused, each naming its path
// and never its value.
func TestComputeBlockUnknownKeyRefused(t *testing.T) {
	for source, want := range map[string]string{
		`{"compute": {"floor": "AP"}}`:                                                                     "compute: invalid acl policy: an unknown key",
		`{"compute": {"search": {"enable": true}}}`:                                                        "compute.search: invalid acl policy: an unknown key",
		`{"compute": {"assurance_floor": "AP", "assurance_floor": "A1"}}`:                                  "a key given twice",
		`{"compute": {"assurance_floor": "A3"}}`:                                                           "compute.assurance_floor: invalid acl policy: an unknown assurance floor",
		`{"compute": {"assurance_floor": "ap"}}`:                                                           "an unknown assurance floor",
		`{"compute": {"enclave_assurance_floor": "none"}}`:                                                 "compute.enclave_assurance_floor: invalid acl policy: an unknown assurance floor",
		`{"compute": {"providers": ["chutes-qwen3.8-27b-tee-high"]}}`:                                      "compute.providers[0]: invalid acl policy: not a name this list takes",
		`{"compute": {"providers": ["*", "chutes"]}}`:                                                      "* beside names",
		`{"compute": {"providers": []}}`:                                                                   "an empty list",
		`{"compute": {"providers": ["chutes", "chutes"]}}`:                                                 "a name given twice",
		`{"compute": {"enclave_shapes": ["CPU-2"]}}`:                                                       "not a name this list takes",
		`{"compute": {"budgets": [{"subjects": ["autogroup:tagged"], "per": "subject"}]}}`:                 "a budget with no amount",
		`{"compute": {"budgets": [{"per": "subject", "day_usd": 1}]}}`:                                     "a budget with no subjects",
		`{"compute": {"budgets": [{"subjects": ["autogroup:tagged"], "day_usd": 1}]}}`:                     "a budget with no per",
		`{"compute": {"budgets": [{"subjects": ["autogroup:tagged"], "per": "device", "day_usd": 1}]}}`:    "an unknown per",
		`{"compute": {"budgets": [{"subjects": ["autogroup:internet"], "per": "subject", "day_usd": 1}]}}`: "a selector this position does not take",
		`{"compute": {"search": {"enabled": "yes"}}}`:                                                      "compute.search.enabled: invalid acl policy: not true or false",
		`{"compute": {"search": {"day_max": 0}}}`:                                                          "not a count of searches",
		`{"compute": {"search": {"day_max": 2.5}}}`:                                                        "not a count of searches",
		`{"compute": {"fetch": {"egress": "direct"}}}`:                                                     "an egress this tool does not take",
		`{"compute": {"fetch": {"egress": "exits"}}}`:                                                      "exits names its exit",
		`{"compute": {"calendar": {"exit": "tag:exit"}}}`:                                                  "exits names its exit",
		`{"compute": {"fetch": {"egress": "exits", "exit": "group:a"}}}`:                                   "an exit that is no tag: or sidecar:",
		`{"compute": {"support": {"egress": "some"}}}`:                                                     "an unknown support egress",
		`{"compute": {"approvals": {"auto": ["dns_set"]}}}`:                                                "a kind automatic approvals do not decide",
		`{"compute": {"approvals": {"auto": ["tainted_send", "tainted_send"]}}}`:                           "a kind given twice",
		`{"compute": {"approvals": {}}}`:                                                                   "approvals with no auto",
		`{"compute": {"disclosures": {"engy": "c3RhdGVtZW50"}}}`:                                           "not a disclosure id",
		`{"compute": {"disclosures": {"inference:Engy": "c3RhdGVtZW50"}}}`:                                 "not a disclosure id",
		`{"compute": {"disclosures": {"inference:engy": "not base64!"}}}`:                                  "a statement that is not standard base64",
		`{"compute": {"history": {}}}`:                                                                     "history with no member_share",
		`{"compute": {"history": {"member_share": "half"}}}`:                                               "a share that is neither auto nor a number",
		`{"compute": {"history": {"member_share": 0.01}}}`:                                                 "a share outside its bounds",
		`{"compute": {"history": {"member_share": 1.5}}}`:                                                  "a share outside its bounds",
		`{"compute": {"history": {"member_share": 0.3333333}}}`:                                            "a share outside its bounds",
		`{"compute": []}`: "compute: invalid acl policy: not an object",
	} {
		_, err := ParseAclPolicy([]byte(source))
		if err == nil || !errors.Is(err, ErrAclPolicyInvalid) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", source, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "chutes-qwen") || strings.Contains(err.Error(), "not base64!")) {
			t.Errorf("%s: a refusal repeats its value: %v", source, err)
		}
	}
}

// USD reads exactly as nano-USD: integers only, nine places at most, no sign or exponent, nothing past the bound.
func TestComputeBlockUsdToNanoExact(t *testing.T) {
	settings := DefaultAclComputeBlockSettings()
	for text, want := range map[string]uint64{
		"5": 5_000_000_000, "0.000000001": 1, "100.5": 100_500_000_000, "1.10": 1_100_000_000, "0.3": 300_000_000,
		"19.999999999": 19_999_999_999, "1000000": settings.BudgetMaxNanoUsd,
	} {
		block := testComputeBlockParsed(t, `{"compute": {"budgets": [{"subjects": ["autogroup:tagged"], "per": "agent", "day_usd": `+text+`}]}}`)
		if got := block.Budgets[0].DayNanoUsd; got != want {
			t.Errorf("%s USD read as %d nano-USD, want %d", text, got, want)
		}
	}
	for _, text := range []string{"0", "0.0", "0.0000000001", "1e3", "1E-9", "-1", "1000000.000000001", "18446744073709551616", `"5"`} {
		source := `{"compute": {"budgets": [{"subjects": ["autogroup:tagged"], "per": "agent", "month_usd": ` + text + `}]}}`
		if _, err := ParseAclPolicy([]byte(source)); err == nil {
			t.Errorf("%s USD was taken", text)
		}
	}
}

// history.member_share reads auto or a share from 0.05 to 1 at most six places, as millionths (§24.10, Q-CTXH-16).
func TestComputeBlockHistoryShare(t *testing.T) {
	for text, want := range map[string]uint32{"0.05": 50_000, "1": 1_000_000, "1.0": 1_000_000, "0.333333": 333_333, "0.5": 500_000} {
		block := testComputeBlockParsed(t, `{"compute": {"history": {"member_share": `+text+`}}}`)
		if block.History.MemberShareAuto || block.History.MemberSharePpm != want {
			t.Errorf("%s read as %+v", text, block.History)
		}
	}
	if block := testComputeBlockParsed(t, `{"compute": {"history": {"member_share": "auto"}}}`); !block.History.MemberShareAuto {
		t.Errorf("auto read as %+v", block.History)
	}
	for _, text := range []string{"0.049999", "0", "1.000001", "2", "-0.5", `"Auto"`, "true"} {
		if _, err := ParseAclPolicy([]byte(`{"compute": {"history": {"member_share": ` + text + `}}}`)); err == nil {
			t.Errorf("a share of %s was taken", text)
		}
	}
}

// The block-alone record holds the compute key and no other; a document's other keys refuse it.
func TestComputeBlockRecordHoldsTheBlockAlone(t *testing.T) {
	block, err := ParseAclComputeRecord([]byte(`// the network's block alone
{"compute": {"fetch": {"enabled": false}},}`))
	if err != nil || block == nil || *block.Fetch.Enabled {
		t.Fatalf("a record: %+v, %v", block, err)
	}
	for _, source := range []string{
		`{}`,
		`{"grants": []}`,
		`{"compute": {}, "grants": []}`,
		`{"grants": [], "compute": {}}`,
		`{"compute": {}, "expiresDefault": "1h"}`,
	} {
		if _, err := ParseAclComputeRecord([]byte(source)); !errors.Is(err, ErrAclComputeRecordInvalid) || !errors.Is(err, ErrAclPolicyInvalid) {
			t.Errorf("%s: %v", source, err)
		}
	}
	if _, err := ParseAclComputeRecord([]byte(`{"compute": {"floor": "A1"}}`)); !errors.Is(err, ErrAclPolicyInvalid) {
		t.Errorf("a record with an unknown key: %v", err)
	}
}
