//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"errors"
	"testing"
)

// The floor order none < AP < A1 < A2 (§16.4), with local admitted under every floor (CO-9, D-INFER-7), a floor that
// is no floor admitting local alone, and a label the device does not know meeting nothing.
func TestComputeLabelFloorMatrix(t *testing.T) {
	floors := []ComputeLabel{ComputeLabelNone, ComputeLabelAp, ComputeLabelA1, ComputeLabelA2, ComputeLabelLocal, "", "A3", "ap"}
	meets := map[ComputeLabel][]ComputeLabel{
		ComputeLabelLocal: floors,
		ComputeLabelA2:    {ComputeLabelNone, ComputeLabelAp, ComputeLabelA1, ComputeLabelA2},
		ComputeLabelA1:    {ComputeLabelNone, ComputeLabelAp, ComputeLabelA1},
		ComputeLabelAp:    {ComputeLabelNone, ComputeLabelAp},
		ComputeLabelNone:  {ComputeLabelNone},
		"":                {},
		"A3":              {},
		"tee":             {},
		"Local":           {},
	}
	for label, floorsMet := range meets {
		for _, floor := range floors {
			want := false
			for _, met := range floorsMet {
				want = want || met == floor
			}
			if got := label.Meets(floor); got != want {
				t.Errorf("%q meets %q: %t, want %t", label, floor, got, want)
			}
		}
	}
}

// Labels and floors parse exactly as written, and a floor is never local.
func TestComputeLabelParse(t *testing.T) {
	for _, text := range []string{"none", "AP", "A1", "A2", "local"} {
		label, err := ParseComputeLabel(text)
		if err != nil || string(label) != text || !label.Valid() || label.Words() == "" {
			t.Errorf("%q read as %q, %v", text, label, err)
		}
	}
	for _, text := range []string{"", "ap", "a1", "None", "LOCAL", "A3", "tee", "no-tee"} {
		if _, err := ParseComputeLabel(text); !errors.Is(err, ErrComputeLabelUnknown) {
			t.Errorf("%q read as a label", text)
		}
	}
	for _, text := range []string{"none", "AP", "A1", "A2"} {
		if floor, err := ParseComputeFloor(text); err != nil || string(floor) != text {
			t.Errorf("the floor %q read as %q, %v", text, floor, err)
		}
	}
	if _, err := ParseComputeFloor("local"); !errors.Is(err, ErrComputeLabelUnknown) {
		t.Errorf("local read as a floor")
	}
	tees := map[ComputeLabel]bool{ComputeLabelAp: true, ComputeLabelA1: true, ComputeLabelA2: true}
	for _, label := range []ComputeLabel{ComputeLabelNone, ComputeLabelAp, ComputeLabelA1, ComputeLabelA2, ComputeLabelLocal, "A3"} {
		if label.Tee() != tees[label] {
			t.Errorf("%q in a TEE: %t", label, label.Tee())
		}
	}
}

// A network's floor and providers and a person's tee_only (§16.4) admit a local model whatever they say, and a remote
// one only by all three; the zero value admits nothing remote.
func TestComputeAssuranceAdmits(t *testing.T) {
	type admission struct {
		provider string
		label    ComputeLabel
	}
	local := admission{provider: "local", label: ComputeLabelLocal}
	chutes := admission{provider: "chutes", label: ComputeLabelAp}
	engy := admission{provider: "engy", label: ComputeLabelNone}
	strong := admission{provider: "example", label: ComputeLabelA2}
	cases := []struct {
		why       string
		assurance *ComputeAssurance
		admitted  []admission
		refused   []admission
	}{
		{
			why:       "the default",
			assurance: DefaultComputeAssurance(),
			admitted:  []admission{local, chutes, engy, strong},
		},
		{
			why:       "a floor of AP",
			assurance: &ComputeAssurance{Floor: ComputeLabelAp, Providers: []string{"*"}},
			admitted:  []admission{local, chutes, strong},
			refused:   []admission{engy},
		},
		{
			why:       "tee_only under a floor of none",
			assurance: &ComputeAssurance{Floor: ComputeLabelNone, Providers: []string{"*"}, TeeOnly: true},
			admitted:  []admission{local, chutes, strong},
			refused:   []admission{engy},
		},
		{
			why:       "a floor of A1, which tee_only cannot lower",
			assurance: &ComputeAssurance{Floor: ComputeLabelA1, Providers: []string{"*"}, TeeOnly: true},
			admitted:  []admission{local, strong},
			refused:   []admission{chutes, engy},
		},
		{
			why:       "the providers named",
			assurance: &ComputeAssurance{Floor: ComputeLabelNone, Providers: []string{"engy"}},
			admitted:  []admission{local, engy},
			refused:   []admission{chutes, strong},
		},
		{
			why:       "the strictest, and no provider",
			assurance: &ComputeAssurance{Floor: ComputeLabelA2, Providers: []string{}, TeeOnly: true},
			admitted:  []admission{local},
			refused:   []admission{chutes, engy, strong},
		},
		{
			why:       "the zero value",
			assurance: &ComputeAssurance{},
			admitted:  []admission{local},
			refused:   []admission{chutes, engy, strong},
		},
		{
			why:       "a floor that is no floor",
			assurance: &ComputeAssurance{Floor: "A3", Providers: []string{"*"}},
			admitted:  []admission{local},
			refused:   []admission{chutes, engy, strong},
		},
		{
			why:       "the local label from elsewhere, or a remote label from local",
			assurance: DefaultComputeAssurance(),
			refused: []admission{
				{provider: "chutes", label: ComputeLabelLocal},
				{provider: "local", label: ComputeLabelA2},
				{provider: "example", label: "A3"},
			},
		},
	}
	for _, c := range cases {
		for _, a := range c.admitted {
			if !c.assurance.Admits(a.provider, a.label) {
				t.Errorf("%s refused %s %s", c.why, a.provider, a.label)
			}
		}
		for _, a := range c.refused {
			if c.assurance.Admits(a.provider, a.label) {
				t.Errorf("%s admitted %s %s", c.why, a.provider, a.label)
			}
		}
	}

	// a refusal says why, and only a refusal says anything
	reasons := []struct {
		assurance *ComputeAssurance
		provider  string
		label     ComputeLabel
		want      string
	}{
		{assurance: DefaultComputeAssurance(), provider: "engy", label: ComputeLabelNone, want: ""},
		{assurance: &ComputeAssurance{Floor: ComputeLabelA2}, provider: "local", label: ComputeLabelLocal, want: ""},
		{assurance: &ComputeAssurance{Floor: ComputeLabelA1, Providers: []string{"*"}}, provider: "chutes",
			label: ComputeLabelAp, want: "below the network's assurance floor A1"},
		{assurance: &ComputeAssurance{Floor: ComputeLabelNone, Providers: []string{"*"}, TeeOnly: true}, provider: "engy",
			label: ComputeLabelNone, want: "below the assurance floor AP that tee_only sets"},
		{assurance: &ComputeAssurance{Floor: ComputeLabelNone, Providers: []string{"engy"}}, provider: "chutes",
			label: ComputeLabelAp, want: "its provider is not among the network's allowed providers"},
		{assurance: &ComputeAssurance{}, provider: "chutes", label: ComputeLabelA2, want: "no assurance floor allows a remote model"},
		{assurance: DefaultComputeAssurance(), provider: "chutes", label: "A3", want: "an unknown label"},
		{assurance: DefaultComputeAssurance(), provider: "chutes", label: ComputeLabelLocal,
			want: "the local label is this device's models' alone"},
	}
	for _, c := range reasons {
		if got := c.assurance.Refusal(c.provider, c.label); got != c.want {
			t.Errorf("%+v, %s %s: %q, want %q", c.assurance, c.provider, c.label, got, c.want)
		}
		if c.assurance.Admits(c.provider, c.label) != (c.want == "") {
			t.Errorf("%+v, %s %s: admitted %t with the reason %q", c.assurance, c.provider, c.label,
				c.assurance.Admits(c.provider, c.label), c.want)
		}
	}

	floors := []struct {
		assurance *ComputeAssurance
		want      ComputeLabel
	}{
		{assurance: DefaultComputeAssurance(), want: ComputeLabelNone},
		{assurance: &ComputeAssurance{Floor: ComputeLabelNone, TeeOnly: true}, want: ComputeLabelAp},
		{assurance: &ComputeAssurance{Floor: ComputeLabelAp, TeeOnly: true}, want: ComputeLabelAp},
		{assurance: &ComputeAssurance{Floor: ComputeLabelA1, TeeOnly: true}, want: ComputeLabelA1},
		{assurance: &ComputeAssurance{Floor: ComputeLabelA2}, want: ComputeLabelA2},
		{assurance: &ComputeAssurance{}, want: ""},
		{assurance: &ComputeAssurance{Floor: ComputeLabelLocal, TeeOnly: true}, want: ""},
	}
	for _, c := range floors {
		if got := c.assurance.EffectiveFloor(); got != c.want {
			t.Errorf("%+v's floor is %q, want %q", c.assurance, got, c.want)
		}
	}
}
