//go:build !js && !ios && !android && !sdk_mobile_bind

// CSURF-M11-02's MCP rows: DESIGN-COMPUTE §15.2's tools in §16.5's table, each registered or listed unbuilt, a compute
// tool registered and still listed passing as CONTRACTS C-29 lets it while a §16.5 tool so registered fails, every
// registered compute tool held to its row whether listed or not, none taking uses, and nothing in the table or the
// daemon's catalog that buys, redeems, renews, refunds, infers, fetches, asks for a connection or acknowledges a
// disclosure (§14.3, Q-FETCH-5, Q-CONN-12, D-CSURF-1).

package mcp

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The daemon's catalog with §15.2's rows: the check passes, and the compute tools whose areas landed and register once
// their rows are here, BAL-M12-20's two and SKILL-M11-07's eight, are in it at their rows while still listed. With the
// support switch on, support's three join and the check still passes.
func TestComputeRowsPassTheCatalogCheck(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	catalog := NewDaemonMcpCatalog(server, nil)
	if err := checkMcpCatalog(catalog); err != nil {
		t.Fatal(err)
	}
	names := catalog.Names()
	joined := []string{mcpToolComputeBalance, mcpToolComputeSpend}
	for _, spec := range sidecar.AgentToolSpecs() {
		joined = append(joined, spec.Name)
	}
	for _, name := range joined {
		if !slices.Contains(names, name) {
			t.Errorf("%s has its row and is not registered", name)
		}
		if !slices.Contains(mcpCatalogUnbuilt, name) {
			t.Errorf("%s left the unbuilt list, which the review phase prunes (C-29)", name)
		}
	}

	server.settings.Support = sidecar.DefaultSupportSettings()
	server.settings.Support.ServiceEnabled = true
	switchedOn := NewDaemonMcpCatalog(server, nil)
	if err := checkMcpCatalog(switchedOn); err != nil {
		t.Fatalf("with the support switch on: %v", err)
	}
	for _, name := range []string{"support_send", "support_list", "support_read"} {
		if !slices.Contains(switchedOn.Names(), name) {
			t.Errorf("%s is not registered with the switch on", name)
		}
	}
}

// Every §15.2 row is a compute row taking no uses (owner decision 613), each owned, W where it may act, and listed
// unbuilt; no §16.5 row is a compute row, so C-29's exception reaches §15.2 alone.
func TestComputeRowsTakeNoUsesAndStayListed(t *testing.T) {
	computeCount := 0
	for _, design := range mcpCatalogDesign {
		if !design.compute {
			continue
		}
		computeCount += 1
		if design.multiUse {
			t.Errorf("%s takes uses", design.name)
		}
		if design.owner == "" {
			t.Errorf("%s has no owner", design.name)
		}
		if design.mayAct && design.tier != McpTierWrite {
			t.Errorf("%s may act at %s", design.name, design.tier)
		}
		if !slices.Contains(mcpCatalogUnbuilt, design.name) {
			t.Errorf("%s is not listed unbuilt", design.name)
		}
	}
	// §15.2's twenty-five tools and §28.4's three support tools it lists beside them
	if computeCount != 28 {
		t.Errorf("%d compute rows", computeCount)
	}
	for _, name := range []string{"evs_write", "mail_send", "search", "directory_request", "run_restore"} {
		index := slices.IndexFunc(mcpCatalogDesign, func(design mcpCatalogDesignTool) bool { return design.name == name })
		if index < 0 || mcpCatalogDesign[index].compute {
			t.Errorf("%s is no §16.5 row or is a compute row", name)
		}
	}
}

// Words a tool's name may not hold (§15.2's closing rules): no tool buys, checks out, renews, refunds, redeems or
// takes a promotion code (§14.3), raises a budget, which is the Harness's alone (§7.5), infers or lists models, which
// external harnesses get through the gateway, fetches (Q-FETCH-5), or acknowledges a disclosure or terms (D-CSURF-1,
// §21.9).
var testComputeMcpForbiddenWords = []string{
	"buy", "checkout", "purchase", "renew", "refund", "redeem", "promo", "promotion", "raise",
	"infer", "inference", "model", "models", "fetch",
	"ack", "acknowledge", "disclosure", "disclosures", "terms", "accept",
}

// Names §15.2 rules out whole: an agent's connection_request, which only a person in the apps or at the terminal answers
// (Q-CONN-12).
var testComputeMcpForbiddenNames = []string{"connection_request", "web_fetch", "models_list"}

// The name's findings against the forbidden words and names, by its _ separated words.
func testComputeMcpForbiddenFindings(names []string) []string {
	findings := []string{}
	for _, name := range names {
		if slices.Contains(testComputeMcpForbiddenNames, name) {
			findings = append(findings, name)
			continue
		}
		for _, word := range strings.Split(name, "_") {
			if slices.Contains(testComputeMcpForbiddenWords, word) {
				findings = append(findings, name+" ("+word+")")
			}
		}
	}
	return findings
}

// Neither the design table nor the daemon's catalog, with every switch on, holds a tool that buys, redeems, infers,
// fetches, asks for a connection or acknowledges; a planted row of each kind is found.
func TestComputeMcpDesignHasNoBuyOrAckTool(t *testing.T) {
	designNames := []string{}
	for _, design := range mcpCatalogDesign {
		designNames = append(designNames, design.name)
	}
	if findings := testComputeMcpForbiddenFindings(designNames); len(findings) != 0 {
		t.Errorf("the design table holds %v", findings)
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	server.settings.Support = sidecar.DefaultSupportSettings()
	server.settings.Support.ServiceEnabled = true
	if findings := testComputeMcpForbiddenFindings(NewDaemonMcpCatalog(server, nil).Names()); len(findings) != 0 {
		t.Errorf("the daemon's catalog holds %v", findings)
	}
	planted := []string{
		"compute_buy", "compute_checkout", "compute_auto_renew", "compute_refund", "compute_redeem", "promo_apply",
		"compute_budget_raise", "models_list", "infer", "web_fetch", "connection_request", "disclosure_ack",
		"compute_terms_accept",
	}
	findings := testComputeMcpForbiddenFindings(planted)
	for _, name := range planted {
		if !slices.ContainsFunc(findings, func(finding string) bool { return strings.HasPrefix(finding, name) }) {
			t.Errorf("a planted %s is not found: %v", name, findings)
		}
	}
}

// C-29 for §15.2's rows alone: a compute tool registered and still listed passes, one neither registered nor listed
// fails naming its owner, one registered at another tier fails though listed, and a §16.5 tool registered and still
// listed fails as before.
func TestComputeRowsMayStayListedOnceRegistered(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	none := func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil }
	echo := func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
		return &testToolOut{}, nil
	}
	design := []mcpCatalogDesignTool{
		{name: "compute_listed", tier: McpTierRead, owner: "PLANTED-1", compute: true},
		{name: "compute_missing", tier: McpTierRead, owner: "PLANTED-2", compute: true},
		{name: "compute_wrong_tier", tier: McpTierOutward, owner: "PLANTED-3", compute: true},
		{name: "plain_listed", tier: McpTierRead, owner: "PLANTED-4"},
	}
	unbuilt := []string{"compute_listed", "compute_wrong_tier", "plain_listed"}

	catalog := NewMcpCatalog(server.settings.Mcp, clock, nil)
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "compute_listed", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "compute_wrong_tier", Tier: McpTierWrite, Description: "writes", Access: none}, echo)
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "plain_listed", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	err := checkMcpCatalogAgainst(catalog, design, unbuilt)
	if err == nil {
		t.Fatal("the planted catalog passes")
	}
	for _, want := range []string{
		"compute_missing (PLANTED-2) is neither registered nor listed unbuilt",
		"compute_wrong_tier is not O with its hints",
		"plain_listed is registered and still listed unbuilt",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("no %q in %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "compute_listed") || strings.Contains(err.Error(), "compute_wrong_tier is registered") {
		t.Errorf("a compute tool registered and still listed fails: %v", err)
	}

	// the same tools with the compute ones registered right, listed or not, pass
	right := NewMcpCatalog(server.settings.Mcp, clock, nil)
	AddTool(right, &McpToolSpec[testToolIn]{Name: "compute_listed", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	AddTool(right, &McpToolSpec[testToolIn]{Name: "compute_missing", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	AddTool(right, &McpToolSpec[testToolIn]{Name: "compute_wrong_tier", Tier: McpTierOutward, Description: "acts", Access: none}, echo)
	AddTool(right, &McpToolSpec[testToolIn]{Name: "plain_listed", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	if err := checkMcpCatalogAgainst(right, design, []string{"compute_listed", "compute_wrong_tier"}); err != nil {
		t.Errorf("a right catalog: %v", err)
	}
}
