//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// A registry of tools whose schemas take tokenEach tokens each, for profiles, named in order.
func harnessBudgetRegistry(tokenEach int, names []string, profiles ...HarnessProfile) *HarnessToolRegistry {
	specs := []*HarnessToolSpec{}
	for _, name := range names {
		// four bytes a token, less what the name takes
		schema := `{"type":"object","description":"` + strings.Repeat("x", tokenEach*4-len(name)-len(`{"type":"object","description":""}`)) + `"}`
		specs = append(specs, harnessTestSpec(&harnessTestTool{name: name, schema: []byte(schema)}, true, profiles...))
	}
	return harnessTestRegistry(specs...)
}

// A 32k-token window's agent naming no tools gets the profile's whole set where it fits, else the small set, each
// small tool the profile serves, in the small set's order.
func TestHarnessToolBudgetFallsBackToSmallSet(t *testing.T) {
	settings := DefaultHarnessSettings()
	entry := &InferCatalogEntry{ContextWindow: 32768}
	budget := harnessToolBudget(settings, entry)
	if budget != 8192 {
		t.Fatalf("a 32k window's budget is %d", budget)
	}
	extra := []string{}
	for i := 0; i < 40; i += 1 {
		extra = append(extra, "extra_tool_"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	small := []string{"read", "write", "edit", "ls", "grep", "evs_read", "agent_send"}
	registry := harnessBudgetRegistry(300, append(slices.Clone(small), extra...), HarnessProfileLocal)
	skill := strings.Repeat("s", 4*1500)
	set, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, nil, skill, budget)
	if err != nil {
		t.Fatal(err)
	}
	if !set.small || !slices.Equal(set.names, small) {
		t.Fatalf("a 32k window got %v (small %v)", set.names, set.small)
	}
	// a 200k window fits the whole set
	large := harnessToolBudget(settings, &InferCatalogEntry{ContextWindow: 200000})
	set, err = newHarnessToolSet(settings, registry, HarnessProfileLocal, nil, skill, large)
	if err != nil {
		t.Fatal(err)
	}
	if set.small || len(set.names) != len(small)+len(extra) {
		t.Fatalf("a 200k window got %d tools (small %v)", len(set.names), set.small)
	}
	// the catalog's own budget wins over the fraction
	if got := harnessToolBudget(settings, &InferCatalogEntry{ContextWindow: 32768, ToolBudget: 1000}); got != 1000 {
		t.Fatalf("the catalog's budget read as %d", got)
	}
}

// A spec naming more than the budget holds is refused before the agent starts.
func TestHarnessSpecPastBudgetRefused(t *testing.T) {
	settings := DefaultHarnessSettings()
	registry := harnessBudgetRegistry(3000, []string{"read", "write", "edit", "grep"}, HarnessProfileLocal)
	budget := harnessToolBudget(settings, &InferCatalogEntry{ContextWindow: 32768})
	if _, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, []string{"read", "write", "edit"}, "", budget); !errors.Is(err, ErrHarnessToolBudget) {
		t.Fatalf("three 3,000-token tools in an 8,192-token budget: %v", err)
	}
	set, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, []string{"read", "write"}, "", budget)
	if err != nil || !slices.Equal(set.names, []string{"read", "write"}) {
		t.Fatalf("two tools: %v, %v", set, err)
	}
	if _, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, []string{"read"}, strings.Repeat("s", 4*6000), budget); !errors.Is(err, ErrHarnessToolBudget) {
		t.Fatalf("a skill past the budget: %v", err)
	}
}

// bash is the enclave profile's: a spec naming it in the local profile is refused, as is a name no tool registers.
func TestHarnessSpecNamingBashInLocalRefused(t *testing.T) {
	settings := DefaultHarnessSettings()
	registry := harnessTestRegistry(
		harnessTestSpec(&harnessTestTool{name: "read"}, true, HarnessProfileLocal, HarnessProfileEnclave),
		harnessTestSpec(&harnessTestTool{name: "bash", tier: HarnessToolTierWrite}, true, HarnessProfileEnclave),
	)
	budget := harnessToolBudget(settings, &InferCatalogEntry{ContextWindow: 200000})
	if _, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, []string{"read", "bash"}, "", budget); !errors.Is(err, ErrHarnessToolOutsideProfile) {
		t.Fatalf("bash in local: %v", err)
	}
	if _, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, []string{"nonesuch"}, "", budget); !errors.Is(err, ErrHarnessToolOutsideProfile) {
		t.Fatalf("an unregistered name: %v", err)
	}
	set, err := newHarnessToolSet(settings, registry, HarnessProfileEnclave, []string{"read", "bash"}, "", budget)
	if err != nil || len(set.names) != 2 {
		t.Fatalf("bash in an enclave: %v", err)
	}
	// the local profile's whole set holds no bash
	whole, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, nil, "", budget)
	if err != nil || slices.Contains(whole.names, "bash") {
		t.Fatalf("the local set: %v, %v", whole.names, err)
	}
}
