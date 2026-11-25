package computeservice

// The adapter's interface and its base (PROV-M12-01; DESIGN-COMPUTE §4.6): ComputeProviderBase answers every call not
// offered, the slugs' codes are fixed, and a direct target comes from the policy alone (§5.4).

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Every method of ComputeProvider, called on the base with zero arguments, answers ErrComputeNotOffered, but Id, which
// answers the base's slug, and Payment, which answers none; and every method of the interface is one of those called,
// so a method added to the interface without its base answer fails here before an adapter could inherit a silent one.
func TestComputeProviderBaseAnswersNotOffered(t *testing.T) {
	base := &ComputeProviderBase{ProviderId: ComputeProviderIdEngy}
	interfaceType := reflect.TypeOf((*ComputeProvider)(nil)).Elem()
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	value := reflect.ValueOf(base)
	called := 0
	for i := range interfaceType.NumMethod() {
		method := interfaceType.Method(i)
		function := value.MethodByName(method.Name)
		args := []reflect.Value{}
		for j := range function.Type().NumIn() {
			argType := function.Type().In(j)
			if argType == contextType {
				args = append(args, reflect.ValueOf(context.Background()))
			} else {
				args = append(args, reflect.Zero(argType))
			}
		}
		results := function.Call(args)
		called += 1
		switch method.Name {
		case "Id":
			if id := results[0].Interface().(ComputeProviderId); id != ComputeProviderIdEngy {
				t.Errorf("Id answered %q", id)
			}
			continue
		case "Payment":
			if payment := results[0].Interface().(ComputeProviderPayment); payment.Method != ComputeProviderPaymentNone || payment.Netuid != 0 {
				t.Errorf("Payment answered %+v", payment)
			}
			continue
		}
		last := results[len(results)-1]
		if last.Type() != errorType {
			t.Errorf("%s answers no error, so the base cannot say it is not offered", method.Name)
			continue
		}
		err, _ := last.Interface().(error)
		if !errors.Is(err, ErrComputeNotOffered) {
			t.Errorf("%s answered %v", method.Name, err)
		}
		for _, result := range results[:len(results)-1] {
			if !result.IsZero() {
				t.Errorf("%s answered %v beside not offered", method.Name, result)
			}
		}
	}
	if called != interfaceType.NumMethod() || called != 15 {
		t.Fatalf("called %d of the interface's %d methods; §4.6 writes 15", called, interfaceType.NumMethod())
	}
}

// Each slug's code, kind and gate are the ones compute_charge rows were written under: a code is an identifier, fixed
// for good, so any change to this table is a change to every charge already written (§9.4, QD-1247).
func TestComputeProviderSlugCodesAreFixed(t *testing.T) {
	want := []struct {
		id   ComputeProviderId
		code ComputeProviderCode
		kind ComputeProviderKind
		gate string
	}{
		{id: "chutes", code: 1, kind: ComputeProviderKindInference, gate: "G-PROV-chutes"},
		{id: "engy", code: 2, kind: ComputeProviderKindInference, gate: "G-PROV-engy"},
		{id: "saygm", code: 3, kind: ComputeProviderKindInference, gate: "G-PROV-saygm"},
		{id: "hippius", code: 4, kind: ComputeProviderKindEnclave, gate: "G-PROV-hippius"},
		{id: "lium", code: 5, kind: ComputeProviderKindEnclave, gate: "G-PROV-lium"},
		{id: "cathedral", code: 6, kind: ComputeProviderKindEnclave, gate: "G-PROV-cathedral"},
		{id: "reference", code: 7, kind: ComputeProviderKindEnclave, gate: "G-PROV-reference"},
		{id: "parallel", code: 8, kind: ComputeProviderKindSearch, gate: "G-SRCH-parallel"},
	}
	ids := ComputeProviderIds()
	if len(ids) != len(want) {
		t.Fatalf("this build knows %d providers: %v", len(ids), ids)
	}
	for i, w := range want {
		if ids[i] != w.id {
			t.Errorf("provider %d is %q, want %q", i, ids[i], w.id)
		}
		code, known := ComputeProviderCodeOf(w.id)
		if !known || code != w.code {
			t.Errorf("%s's code is %d, want %d", w.id, code, w.code)
		}
		id, known := ComputeProviderIdOf(w.code)
		if !known || id != w.id {
			t.Errorf("code %d names %q, want %q", w.code, id, w.id)
		}
		kind, _ := ComputeProviderKindOf(w.id)
		gate, _ := ComputeProviderGateOf(w.id)
		if kind != w.kind || gate != w.gate {
			t.Errorf("%s is %s gated by %s, want %s by %s", w.id, kind, gate, w.kind, w.gate)
		}
		for _, c := range string(w.id) {
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
				t.Errorf("%q is no slug", w.id)
			}
		}
	}
	if _, known := ComputeProviderIdOf(ComputeProviderCodeNone); known {
		t.Error("code 0, a charge with no provider, names a provider")
	}
	if _, known := ComputeProviderCodeOf("bittensor-sn64"); known {
		t.Error("a slug no table names has a code")
	}
}

// A policy whose direct line lists engy with one model and one target.
func testDirectPolicy() *sidecar.ComputePolicy {
	return &sidecar.ComputePolicy{
		Version: 1,
		Direct: sidecar.ComputePolicyDirectLine{
			Providers: []*sidecar.ComputePolicyDirect{
				{
					Slug:           "engy",
					ApiHost:        "api.engy.example",
					ReceiverHotkey: "5ReceiverHotkeyOfTheTestPolicy",
					Netuid:         53,
					Targets: []*sidecar.ComputePolicyDirectTarget{
						{Method: "POST", Path: "/v1/chat/completions"},
					},
					Models: []*sidecar.ComputePolicyDirectModel{
						{
							Model:           "deepseek-v4.1-flash",
							ProviderModelId: "deepseek-ai/DeepSeek-V4.1-Flash-1017",
							Aliases:         []string{"deepseek-v4.1-flash"},
							ZeroRetention:   true,
						},
					},
				},
			},
		},
	}
}

// The target is the policy's, field for field, and nothing makes one the policy does not list: no policy, a provider,
// a model or a target off its direct line, or an entry missing its host, receiver or provider model id.
func TestComputeDirectTargetComesFromThePolicyAlone(t *testing.T) {
	policy := testDirectPolicy()
	target, err := computeDirectTargetFromPolicy(policy, ComputeProviderIdEngy, "deepseek-v4.1-flash", "POST", "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "api.engy.example" || target.ReceiverHotkey != "5ReceiverHotkeyOfTheTestPolicy" || target.Netuid != 53 ||
		target.ProviderModelId != "deepseek-ai/DeepSeek-V4.1-Flash-1017" || !target.ZeroRetention ||
		!slices.Equal(target.Aliases, []string{"deepseek-v4.1-flash"}) || target.Method != "POST" || target.Path != "/v1/chat/completions" {
		t.Fatalf("the target reads %+v", target)
	}
	// a copy: an answer's caller cannot change the policy's lists
	target.Aliases[0] = "changed"
	if policy.Direct.Providers[0].Models[0].Aliases[0] != "deepseek-v4.1-flash" {
		t.Fatal("the target shares the policy's aliases")
	}

	incomplete := testDirectPolicy()
	incomplete.Direct.Providers[0].ReceiverHotkey = ""
	cases := []struct {
		label    string
		policy   *sidecar.ComputePolicy
		provider ComputeProviderId
		model    string
		method   string
		path     string
	}{
		{label: "no policy", policy: nil, provider: ComputeProviderIdEngy, model: "deepseek-v4.1-flash", method: "POST", path: "/v1/chat/completions"},
		{label: "a provider off the line", policy: policy, provider: ComputeProviderIdSaygm, model: "deepseek-v4.1-flash", method: "POST", path: "/v1/chat/completions"},
		{label: "a model off the line", policy: policy, provider: ComputeProviderIdEngy, model: "qwen3.6-35b-a3b", method: "POST", path: "/v1/chat/completions"},
		{label: "a provider's own id for the model", policy: policy, provider: ComputeProviderIdEngy, model: "deepseek-ai/DeepSeek-V4.1-Flash-1017", method: "POST", path: "/v1/chat/completions"},
		{label: "a target off the line", policy: policy, provider: ComputeProviderIdEngy, model: "deepseek-v4.1-flash", method: "POST", path: "/v1/completions"},
		{label: "another method", policy: policy, provider: ComputeProviderIdEngy, model: "deepseek-v4.1-flash", method: "GET", path: "/v1/chat/completions"},
		{label: "an entry without its receiver", policy: incomplete, provider: ComputeProviderIdEngy, model: "deepseek-v4.1-flash", method: "POST", path: "/v1/chat/completions"},
	}
	for _, c := range cases {
		if target, err := computeDirectTargetFromPolicy(c.policy, c.provider, c.model, c.method, c.path); err == nil || target != nil {
			t.Errorf("%s: made %+v", c.label, target)
		}
	}
}
