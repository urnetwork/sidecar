//go:build !ios_extension && !sidecar_http

// ComputeModelGate (DESIGN-COMPUTE §16.4, D-CACL-4; CACL-M11-01): a local model held to allow alone, tee_only a floor of
// AP, a glob that never reads as a label, and each refusal naming its rule.

package sidecar

import (
	"errors"
	"testing"
)

// The rule a gate's answer names, empty for none.
func testComputeModelRule(t *testing.T, err error) ComputeModelRule {
	t.Helper()
	if err == nil {
		return ""
	}
	refused := &ComputeModelRefusedError{}
	if !errors.As(err, &refused) || !errors.Is(err, ErrComputeModelRefused) {
		t.Fatalf("a refusal that names no rule: %v", err)
	}
	return refused.Rule
}

func TestComputeModelGateLocalChecksAllowAlone(t *testing.T) {
	infer := DefaultInferSettings()
	// the strictest network and person: a floor of A2, one provider, tee_only on
	network := &ComputeNetworkModels{Floor: ComputeLabelA2, Providers: []string{"chutes"}}
	key := &HarnessModelsKeyRead{Key: &HarnessModelsKey{TeeOnly: true}}
	gate := NewComputeModelGate(network, key, infer)
	if err := gate.Allows("local-gemma-4-e4b-off", ComputeLabelLocal); err != nil {
		t.Fatalf("a local model under every limit: %v", err)
	}
	// a remote AP model fails the floor there
	if rule := testComputeModelRule(t, gate.Allows("chutes-qwen3.8-27b-tee-high", ComputeLabelAp)); rule != ComputeModelRuleFloor {
		t.Fatalf("an AP model under A2: %s", rule)
	}
	// allow is the one limit a local model meets
	key.Key.Allow = []string{"chutes-*"}
	if rule := testComputeModelRule(t, NewComputeModelGate(network, key, infer).Allows("local-gemma-4-e4b-off", ComputeLabelLocal)); rule != ComputeModelRuleAllow {
		t.Fatalf("a local model off allow: %s", rule)
	}
	key.Key.Allow = []string{"local-gemma-*"}
	if err := NewComputeModelGate(network, key, infer).Allows("local-gemma-4-e4b-off", ComputeLabelLocal); err != nil {
		t.Fatalf("a local model on allow: %v", err)
	}
	// the local label is the device's models' alone, and a local name takes no other
	if rule := testComputeModelRule(t, gate.Allows("chutes-qwen3.8-27b-tee-high", ComputeLabelLocal)); rule != ComputeModelRuleFloor {
		t.Fatalf("a remote model labeled local: %s", rule)
	}
	if rule := testComputeModelRule(t, NewComputeModelGate(nil, nil, infer).Allows("local-gemma-4-e4b-off", ComputeLabelA2)); rule != ComputeModelRuleFloor {
		t.Fatalf("a local model labeled A2: %s", rule)
	}
	if rule := testComputeModelRule(t, NewComputeModelGate(nil, nil, infer).Allows("chutes-qwen3.8-27b-high", ComputeLabel("tee"))); rule != ComputeModelRuleFloor {
		t.Fatalf("an unknown label: %s", rule)
	}
	// a name outside §6.3's grammar is no model at all
	if err := gate.Allows("Chutes-Model", ComputeLabelA2); !errors.Is(err, ErrInferModelNameInvalid) {
		t.Fatalf("a bad name: %v", err)
	}
}

func TestComputeModelGateTeeOnlyIsApFloor(t *testing.T) {
	infer := DefaultInferSettings()
	key := &HarnessModelsKeyRead{Key: &HarnessModelsKey{TeeOnly: true}}
	gate := NewComputeModelGate(nil, key, infer)
	cases := []struct {
		label ComputeLabel
		rule  ComputeModelRule
	}{
		{label: ComputeLabelNone, rule: ComputeModelRuleTeeOnly},
		{label: ComputeLabelAp},
		{label: ComputeLabelA1},
		{label: ComputeLabelA2},
	}
	for _, c := range cases {
		if rule := testComputeModelRule(t, gate.Allows("chutes-qwen3.8-27b-high", c.label)); rule != c.rule {
			t.Errorf("%s: %s, want %s", c.label, rule, c.rule)
		}
	}
	// off, a none model runs under the network's floor of none (Q-CACL-3's (a))
	if err := NewComputeModelGate(nil, &HarnessModelsKeyRead{Key: &HarnessModelsKey{}}, infer).Allows("chutes-qwen3.8-27b-high", ComputeLabelNone); err != nil {
		t.Fatalf("tee_only off: %v", err)
	}
	// a network floor above AP is not lowered by tee_only
	network := &ComputeNetworkModels{Floor: ComputeLabelA1, Providers: []string{"*"}}
	if rule := testComputeModelRule(t, NewComputeModelGate(network, key, infer).Allows("chutes-qwen3.8-27b-high", ComputeLabelAp)); rule != ComputeModelRuleFloor {
		t.Fatalf("AP under a floor of A1 with tee_only: %s", rule)
	}
}

func TestComputeModelGateGlobReadsNoLabel(t *testing.T) {
	infer := DefaultInferSettings()
	// a glob naming the -tee mark is a pattern over names, never a label: SayGM's -tee names are labeled none (R1-56)
	key := &HarnessModelsKeyRead{Key: &HarnessModelsKey{Allow: []string{"*-tee-*"}}}
	gate := NewComputeModelGate(nil, key, infer)
	if err := gate.Allows("saygm-qwen3-tee-high", ComputeLabelNone); err != nil {
		t.Fatalf("a none model whose name matches the glob: %v", err)
	}
	if rule := testComputeModelRule(t, gate.Allows("chutes-qwen3.8-27b-high", ComputeLabelA2)); rule != ComputeModelRuleAllow {
		t.Fatalf("an A2 model whose name does not match: %s", rule)
	}
	// TEE-only is tee_only or the floor, which refuse the none model the glob matched
	key.Key.TeeOnly = true
	if rule := testComputeModelRule(t, NewComputeModelGate(nil, key, infer).Allows("saygm-qwen3-tee-high", ComputeLabelNone)); rule != ComputeModelRuleTeeOnly {
		t.Fatalf("tee_only beside the glob: %s", rule)
	}
	matches := []struct {
		glob  string
		name  string
		match bool
	}{
		{glob: "*", name: "chutes-qwen3.8-27b-tee-high", match: true},
		{glob: "chutes-*", name: "chutes-qwen3.8-27b-tee-high", match: true},
		{glob: "chutes-*", name: "chutesx-qwen-high", match: false},
		{glob: "*-high", name: "chutes-qwen-high", match: true},
		{glob: "*-high", name: "chutes-qwen-higher", match: false},
		{glob: "chutes-*-tee-*", name: "chutes-qwen3.8-27b-tee-high", match: true},
		{glob: "chutes-*-tee-*", name: "chutes-qwen3.8-27b-high", match: false},
		{glob: "a*a", name: "a", match: false},
		{glob: "local-gemma-4-e4b-off", name: "local-gemma-4-e4b-off", match: true},
		{glob: "local-gemma-4-e4b-off", name: "local-gemma-4-e4b-low", match: false},
	}
	for _, c := range matches {
		if got := harnessModelsGlobMatch(c.glob, c.name); got != c.match {
			t.Errorf("%s against %s: %v", c.glob, c.name, got)
		}
	}
}
