//go:build !ios_extension && !sidecar_http

// The models key (DESIGN-COMPUTE §16.4; CACL-M11-01): each field read and held to its bounds, a write strict where a
// read passes over what a later release may add, and the key narrowing only what the network grants.

package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestModelsKeyParse(t *testing.T) {
	settings, infer := DefaultModelsKeySettings(), DefaultInferSettings()
	full := `{
		"default": "local-gemma-4-e4b-off",
		"allow": ["local-*", "chutes-*", "chutes-qwen3.8-27b-tee-high"],
		"tee_only": true,
		"sign_in_mail": "allow",
		"harness": {"codex": {"model": "chutes-qwen3.8-27b-tee-high"},
		            "claude-code": {"opus": "chutes-qwen3.8-27b-tee-high", "sonnet": "chutes-qwen3.8-27b-tee-medium", "haiku": "local-gemma-4-e4b-off"}},
		"agents": {"reviewer": {"default": "chutes-qwen3.8-27b"}}
	}`
	key, warnings, err := ParseHarnessModelsKey(json.RawMessage(full), true, settings, infer)
	if err != nil {
		t.Fatal(err)
	}
	if key.Default != "local-gemma-4-e4b-off" || len(key.Allow) != 3 || !key.TeeOnly || key.SignInMailMode() != HarnessSignInMailAllow ||
		key.Harness[HarnessModelsCodex][HarnessModelsTierModel] != "chutes-qwen3.8-27b-tee-high" ||
		key.Harness[HarnessModelsClaudeCode][HarnessModelsTierHaiku] != "local-gemma-4-e4b-off" ||
		key.Agents["reviewer"].Default != "chutes-qwen3.8-27b" || len(warnings) != 0 {
		t.Fatalf("parsed %+v, warnings %v", key, warnings)
	}
	// the written form reads back as the same key
	again, _, err := ParseHarnessModelsKey(harnessModelsKeyJson(key), true, settings, infer)
	if err != nil || fmt.Sprintf("%+v", again.Harness) != fmt.Sprintf("%+v", key.Harness) || again.Default != key.Default ||
		strings.Join(again.Allow, ",") != strings.Join(key.Allow, ",") || again.Agents["reviewer"].Default != "chutes-qwen3.8-27b" {
		t.Fatalf("the written form reads %+v, %v", again, err)
	}
	// allow absent is every model, [] is none
	empty, _, err := ParseHarnessModelsKey(json.RawMessage(`{"allow": []}`), true, settings, infer)
	if err != nil || empty.Allow == nil || len(empty.Allow) != 0 {
		t.Fatalf("an empty allow reads %+v, %v", empty, err)
	}

	tooMany := make([]string, settings.AllowMaxCount+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf(`"local-m%d-*"`, i)
	}
	agents := []string{}
	for i := range settings.AgentMaxCount + 1 {
		agents = append(agents, fmt.Sprintf(`"agent%d": {}`, i))
	}
	refused := []string{
		`{"default": "Local-Gemma"}`,
		`{"default": "nohyphen"}`,
		`{"default": 7}`,
		`{"default": null}`,
		`{"allow": "local-*"}`,
		`{"allow": [""]}`,
		`{"allow": ["local-/x"]}`,
		`{"allow": ["` + strings.Repeat("a", infer.NameMaxByteCount+1) + `"]}`,
		`{"allow": ["*-*-*-*-*-x"]}`,
		`{"allow": ["notaname"]}`,
		`{"allow": [` + strings.Join(tooMany, ",") + `]}`,
		`{"tee_only": "yes"}`,
		`{"sign_in_mail": "sometimes"}`,
		`{"harness": {"codex": {"opus": "local-gemma-4-e4b-off"}}}`,
		`{"harness": {"codex": {"model": "BAD"}}}`,
		`{"harness": {"cursor": {"model": "local-gemma-4-e4b-off"}}}`,
		`{"harness": []}`,
		`{"agents": {"-bad": {"default": "local-gemma-4-e4b-off"}}}`,
		`{"agents": {"reviewer": {"default": "BAD"}}}`,
		`{"agents": {"reviewer": {"model": "local-gemma-4-e4b-off"}}}`,
		`{"agents": {` + strings.Join(agents, ",") + `}}`,
		`{"later": true}`,
		`{"tee_only": true, "tee_only": false}`,
	}
	for _, raw := range refused {
		if _, _, err := ParseHarnessModelsKey(json.RawMessage(raw), true, settings, infer); !errors.Is(err, ErrModelsKeyInvalid) {
			t.Errorf("%.80s: %v", raw, err)
		}
	}
	// a read passes over a field, harness or tier this build does not know, naming each
	lenient, warnings, err := ParseHarnessModelsKey(json.RawMessage(
		`{"later": 1, "tee_only": true, "harness": {"cursor": {"model": "x"}, "codex": {"model": "local-gemma-4-e4b-off", "fast": "y"}},
		  "agents": {"reviewer": {"default": "local-gemma-4-e4b-off", "budget": 5}}}`), false, settings, infer)
	if err != nil || !lenient.TeeOnly || lenient.Harness[HarnessModelsCodex][HarnessModelsTierModel] != "local-gemma-4-e4b-off" || len(warnings) != 4 {
		t.Fatalf("a lenient read: %+v, %v, %v", lenient, warnings, err)
	}
	// and still refuses a known field's bad value
	if _, _, err := ParseHarnessModelsKey(json.RawMessage(`{"later": 1, "default": "BAD"}`), false, settings, infer); !errors.Is(err, ErrModelsKeyInvalid) {
		t.Fatalf("a lenient read of a bad default: %v", err)
	}
	// a write holds the key to the same rules
	for _, key := range []*HarnessModelsKey{
		{Default: "BAD"},
		{Allow: []string{"a**b-*-*-*-*"}},
		{SignInMail: "sometimes"},
		{Harness: map[string]map[string]string{"cursor": {"model": "local-gemma-4-e4b-off"}}},
		{Harness: map[string]map[string]string{HarnessModelsClaudeCode: {"model": "local-gemma-4-e4b-off"}}},
		{Agents: map[string]*HarnessModelsAgent{"-bad": {}}},
		{Agents: map[string]*HarnessModelsAgent{"ok": nil}},
	} {
		if err := checkHarnessModelsKey(key, settings, infer); !errors.Is(err, ErrModelsKeyInvalid) {
			t.Errorf("%+v: %v", key, err)
		}
	}
}

func TestModelsKeyNarrowsOnly(t *testing.T) {
	infer := DefaultInferSettings()
	network := &ComputeNetworkModels{Floor: ComputeLabelAp, Providers: []string{"chutes"}}
	// the widest key a person can write: every model, tee_only off
	widest := &HarnessModelsKeyRead{Key: &HarnessModelsKey{Allow: []string{"*"}}}
	gate := NewComputeModelGate(network, widest, infer)
	cases := []struct {
		name  string
		label ComputeLabel
		rule  ComputeModelRule
	}{
		// below the network's floor, whatever the key says
		{name: "chutes-qwen3.8-27b-high", label: ComputeLabelNone, rule: ComputeModelRuleFloor},
		// off the network's providers, whatever the key says
		{name: "saygm-qwen3.8-27b-high", label: ComputeLabelA1, rule: ComputeModelRuleProvider},
		// the network's own grant
		{name: "chutes-qwen3.8-27b-tee-high", label: ComputeLabelAp},
	}
	for _, c := range cases {
		err := gate.Allows(c.name, c.label)
		refused := &ComputeModelRefusedError{}
		switch {
		case c.rule == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.rule != "" && (!errors.As(err, &refused) || refused.Rule != c.rule):
			t.Errorf("%s: %v, want rule %s", c.name, err, c.rule)
		}
	}
	// and a narrower key narrows the network's grant
	narrow := &HarnessModelsKeyRead{Key: &HarnessModelsKey{Allow: []string{"local-*"}}}
	refused := &ComputeModelRefusedError{}
	if err := NewComputeModelGate(network, narrow, infer).Allows("chutes-qwen3.8-27b-tee-high", ComputeLabelAp); !errors.As(err, &refused) || refused.Rule != ComputeModelRuleAllow {
		t.Fatalf("a narrower allow: %v", err)
	}
	teeOnly := &HarnessModelsKeyRead{Key: &HarnessModelsKey{TeeOnly: true}}
	if err := NewComputeModelGate(DefaultComputeNetworkModels(), teeOnly, infer).Allows("chutes-qwen3.8-27b-high", ComputeLabelNone); !errors.As(err, &refused) || refused.Rule != ComputeModelRuleTeeOnly {
		t.Fatalf("tee_only: %v", err)
	}
	// the gate's assurance, which the catalog's list is limited by, carries the person's tee_only
	if assurance := NewComputeModelGate(network, teeOnly, infer).Assurance(); !assurance.TeeOnly || assurance.Floor != ComputeLabelAp {
		t.Fatalf("assurance %+v", assurance)
	}
}

func TestModelsKeyWriteChangesOnlyWhatChanged(t *testing.T) {
	was := &HarnessModelsKey{
		Default: "local-gemma-4-e4b-off",
		Allow:   []string{"local-*"},
		Harness: map[string]map[string]string{HarnessModelsCodex: {HarnessModelsTierModel: "local-gemma-4-e4b-off"}},
		Agents:  map[string]*HarnessModelsAgent{"reviewer": {Default: "local-gemma-4-e4b-off"}, "writer": {}},
	}
	now := was.Clone()
	now.Allow = nil
	now.Harness[HarnessModelsClaudeCode] = map[string]string{HarnessModelsTierOpus: "chutes-qwen3.8-27b-tee-high"}
	delete(now.Agents, "writer")
	now.Agents["planner"] = &HarnessModelsAgent{Default: "chutes-qwen3.8-27b"}
	edits := harnessModelsKeyEdits(was, now)
	got := []string{}
	for _, edit := range edits {
		value := "removed"
		if edit.Value != nil {
			value = string(edit.Value)
		}
		got = append(got, fmt.Sprintf("%s=%s", strings.Join(edit.Path, "."), value))
	}
	want := []string{
		"models.allow=removed",
		`models.harness.claude-code.opus="chutes-qwen3.8-27b-tee-high"`,
		`models.agents.planner={"default":"chutes-qwen3.8-27b"}`,
		"models.agents.writer=removed",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("edits\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(harnessModelsKeyEdits(was, was.Clone())) != 0 {
		t.Fatal("an unchanged key makes edits")
	}
}
