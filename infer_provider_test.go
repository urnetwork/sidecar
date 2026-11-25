//go:build !ios_extension && !sidecar_http

package sidecar

// The device half's seam (PROV-M12-01; DESIGN-COMPUTE §4.6, §6.4, §6.6): halves register by slug and a slug no half
// serves is refused; the effort sent is one the model lists and the half's table maps; a receipt is held to the
// policy's entry.

import (
	"context"
	"errors"
	"testing"
)

// A half for a test: its slug and effort table, every other method refusing.
type testInferProviderHalf struct {
	provider string
	efforts  map[InferEffort]string
}

func (self *testInferProviderHalf) Provider() string {
	return self.provider
}

func (self *testInferProviderHalf) Efforts() map[InferEffort]string {
	return self.efforts
}

func (self *testInferProviderHalf) BuildRequest(args *InferProviderRequestArgs) (*InferProviderRequest, error) {
	return nil, newInferError(InferErrorModelRefused, "a test half builds nothing")
}

func (self *testInferProviderHalf) ReadStream(ctx context.Context, answer *InferProviderAnswer, emit InferEmit) (*InferProviderStreamEnd, error) {
	return nil, newInferError(InferErrorEngineFailed, "a test half reads nothing")
}

func (self *testInferProviderHalf) CheckReceipt(args *InferProviderReceiptArgs) (*InferProviderReceipt, error) {
	return nil, newInferError(InferErrorModelRefused, "a test half checks no receipt")
}

func (self *testInferProviderHalf) Envelope() InferProviderEnvelope {
	return nil
}

// A slug no half serves is model_refused, and so are a constructor that fails and one that builds another provider's
// half; a registered slug builds its half with the settings given.
func TestInferProviderHalfRegistryRefusesUnknownSlug(t *testing.T) {
	settings := DefaultInferSettings()
	var builtWith *InferSettings
	registrations := map[string]InferProviderHalfConstructor{
		"engy": func(settings *InferSettings) (InferProviderHalf, error) {
			builtWith = settings
			return &testInferProviderHalf{provider: "engy"}, nil
		},
		"saygm": func(settings *InferSettings) (InferProviderHalf, error) {
			return nil, errors.New("no upstream pins in this build")
		},
		"chutes": func(settings *InferSettings) (InferProviderHalf, error) {
			return &testInferProviderHalf{provider: "engy"}, nil
		},
	}
	half, err := inferProviderHalfIn(registrations, "engy", settings)
	if err != nil || half.Provider() != "engy" || builtWith != settings {
		t.Fatalf("engy's half: %v, %v", half, err)
	}
	for _, provider := range []string{"targon", "", "local", "saygm", "chutes"} {
		if half, err := inferProviderHalfIn(registrations, provider, settings); half != nil || InferErrorCodeOf(err) != InferErrorModelRefused {
			t.Errorf("%q: %v, %v", provider, half, err)
		}
	}
	// this build registers no provider's half yet, so every slug is refused
	if half, err := inferProviderHalfFor("engy", settings); half != nil || InferErrorCodeOf(err) != InferErrorModelRefused {
		t.Errorf("the build's registry served %v, %v", half, err)
	}
}

// registerInferProviderHalf refuses local, a slug outside [a-z0-9]+, a nil constructor and a second registration.
func TestInferProviderHalfRegistrationRefusals(t *testing.T) {
	saved := inferProviderHalfRegistrations
	t.Cleanup(func() { inferProviderHalfRegistrations = saved })
	inferProviderHalfRegistrations = map[string]InferProviderHalfConstructor{}
	construct := func(settings *InferSettings) (InferProviderHalf, error) {
		return &testInferProviderHalf{provider: "engy"}, nil
	}
	registerInferProviderHalf("engy", construct)
	for label, register := range map[string]func(){
		"local":          func() { registerInferProviderHalf("local", construct) },
		"no slug":        func() { registerInferProviderHalf("Engy", construct) },
		"a hyphen":       func() { registerInferProviderHalf("en-gy", construct) },
		"no constructor": func() { registerInferProviderHalf("saygm", nil) },
		"twice":          func() { registerInferProviderHalf("engy", construct) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			register()
		}()
	}
	if len(inferProviderHalfRegistrations) != 1 {
		t.Fatalf("%d registrations", len(inferProviderHalfRegistrations))
	}
}

// The parameter sent is the half's for an effort the call's entry lists: an effort the entry does not list, or one
// the table lacks, is model_refused, never mapped to a neighbour.
func TestInferProviderEffortFromTheTableOnly(t *testing.T) {
	half := &testInferProviderHalf{provider: "engy", efforts: map[InferEffort]string{
		InferEffortLow:  "low",
		InferEffortHigh: "high",
		InferEffortMax:  "high",
	}}
	entry := &InferCatalogEntry{Provider: "engy", Model: "deepseek-v4.1-flash", Kind: InferCatalogKindDirect, Label: ComputeLabelNone,
		Efforts: []InferEffort{InferEffortOff, InferEffortLow, InferEffortHigh}}
	cases := []struct {
		effort InferEffort
		want   string
		ok     bool
	}{
		{effort: InferEffortLow, want: "low", ok: true},
		{effort: InferEffortHigh, want: "high", ok: true},
		// listed by the entry, absent from the table
		{effort: InferEffortOff, ok: false},
		// in the table, not listed by the entry
		{effort: InferEffortMax, ok: false},
		// neither
		{effort: InferEffortMedium, ok: false},
	}
	for _, c := range cases {
		parameter, err := inferProviderEffort(half, &InferCall{Entry: entry, Effort: c.effort})
		if c.ok != (err == nil) || parameter != c.want {
			t.Errorf("%s: %q, %v", c.effort, parameter, err)
		}
		if err != nil && InferErrorCodeOf(err) != InferErrorModelRefused {
			t.Errorf("%s refused as %v", c.effort, err)
		}
	}
	if _, err := inferProviderEffort(half, &InferCall{Effort: InferEffortLow}); InferErrorCodeOf(err) != InferErrorModelRefused {
		t.Errorf("a call with no entry: %v", err)
	}
}

// A receipt holds where it names the policy's provider id for the model or an alias the gate recorded, with zero
// retention served where the policy requires it; any other model, zero retention not served where required, and no
// receipt or no entry are each model_refused.
func TestInferProviderReceiptModelHeldToThePolicy(t *testing.T) {
	model := &ComputePolicyDirectModel{
		Model:           "deepseek-v4.1-flash",
		ProviderModelId: "deepseek-ai/DeepSeek-V4.1-Flash-1017",
		Aliases:         []string{"deepseek-v4.1-flash"},
		ZeroRetention:   true,
	}
	withoutZdr := &ComputePolicyDirectModel{Model: "qwen3.6-35b-a3b", ProviderModelId: "Qwen/Qwen3.6-35B-A3B"}
	cases := []struct {
		label   string
		receipt *InferProviderReceipt
		model   *ComputePolicyDirectModel
		ok      bool
	}{
		{label: "the provider's id", receipt: &InferProviderReceipt{ServedModelId: "deepseek-ai/DeepSeek-V4.1-Flash-1017", ZeroRetention: true}, model: model, ok: true},
		{label: "an alias", receipt: &InferProviderReceipt{ServedModelId: "deepseek-v4.1-flash", ZeroRetention: true}, model: model, ok: true},
		{label: "another model", receipt: &InferProviderReceipt{ServedModelId: "deepseek-ai/DeepSeek-V4.1-Pro", ZeroRetention: true}, model: model, ok: false},
		{label: "the canonical part, not an alias", receipt: &InferProviderReceipt{ServedModelId: "DeepSeek-V4.1-Flash-1017", ZeroRetention: true}, model: model, ok: false},
		{label: "zero retention not served", receipt: &InferProviderReceipt{ServedModelId: "deepseek-ai/DeepSeek-V4.1-Flash-1017"}, model: model, ok: false},
		{label: "zero retention not required", receipt: &InferProviderReceipt{ServedModelId: "Qwen/Qwen3.6-35B-A3B"}, model: withoutZdr, ok: true},
		{label: "no receipt", receipt: nil, model: model, ok: false},
		{label: "no entry", receipt: &InferProviderReceipt{ServedModelId: "deepseek-ai/DeepSeek-V4.1-Flash-1017", ZeroRetention: true}, model: nil, ok: false},
	}
	for _, c := range cases {
		err := inferProviderCheckReceiptModel(c.receipt, c.model)
		if c.ok != (err == nil) || (err != nil && InferErrorCodeOf(err) != InferErrorModelRefused) {
			t.Errorf("%s: %v", c.label, err)
		}
	}
}
