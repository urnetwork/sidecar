//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One file of testdata/infer/names/: a provider's ids with the model parts they make, and names with their one
// reading.
type testInferNameCorpus struct {
	About    string `json:"about"`
	Provider string `json:"provider"`
	Ids      []struct {
		Id       string `json:"id"`
		Label    string `json:"label"`
		Model    string `json:"model"`
		Refused  bool   `json:"refused"`
		Collides bool   `json:"collides"`
	} `json:"ids"`
	Names []struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
		Effort   string `json:"effort"`
		Invalid  bool   `json:"invalid"`
	} `json:"names"`
}

// §18's corpus of providers' ids: Chutes' -TEE ids, engy's deepseek-v4.1-flash-1017, SayGM's -tee ids labeled none,
// organization prefixes, ids that differ only by organization, ids ending in an effort word, and the grammar's edges.
// Each id makes its model part, or is refused, and says whether it collides; each name gets its one reading; and
// every name a model part makes reads back to that model part and effort.
func TestInferModelNameCorpus(t *testing.T) {
	settings := DefaultInferSettings()
	paths, err := filepath.Glob(filepath.Join("testdata", "infer", "names", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no corpus in testdata/infer/names")
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		corpus := &testInferNameCorpus{}
		if err := decoder.Decode(corpus); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if 0 < len(corpus.Ids) {
			given := make([]*InferProviderModel, len(corpus.Ids))
			for i, id := range corpus.Ids {
				given[i] = &InferProviderModel{Id: id.Id, Label: ComputeLabel(id.Label)}
			}
			results, err := InferNormalizeModelId(corpus.Provider, given, settings)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			for i, id := range corpus.Ids {
				result := results[i]
				if result.Id != id.Id || result.Label != ComputeLabel(id.Label) {
					t.Errorf("%s: %q came back as %q, %s", path, id.Id, result.Id, result.Label)
				}
				if id.Refused != (result.Refused != "") || result.Model != id.Model {
					t.Errorf("%s: %q made %q (refused %q), want %q (refused %t)", path, id.Id, result.Model, result.Refused,
						id.Model, id.Refused)
				}
				if result.Collides != id.Collides {
					t.Errorf("%s: %q collides: %t, want %t", path, id.Id, result.Collides, id.Collides)
				}
				if result.Model == "" {
					continue
				}
				for _, effort := range inferEffortOrder {
					name := corpus.Provider + "-" + result.Model + "-" + string(effort)
					parsed, err := InferParseModelName(name, settings)
					if err != nil || parsed.Provider != corpus.Provider || parsed.Model != result.Model || parsed.Effort != effort {
						t.Errorf("%s: %s does not read back to %s at %s: %+v %v", path, name, result.Model, effort, parsed, err)
					}
				}
			}
		}
		for _, c := range corpus.Names {
			parsed, err := InferParseModelName(c.Name, settings)
			if c.Invalid {
				if !errors.Is(err, ErrInferModelNameInvalid) {
					t.Errorf("%s: %q read as %+v, want it refused", path, c.Name, parsed)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s: %q refused: %v", path, c.Name, err)
				continue
			}
			if parsed.Provider != c.Provider || parsed.Model != c.Model || parsed.Effort != InferEffort(c.Effort) {
				t.Errorf("%s: %q read as %+v, want %s %s %s", path, c.Name, parsed, c.Provider, c.Model, c.Effort)
			}
			if parsed.IsAlias() != (c.Effort == "") || parsed.String() != c.Name {
				t.Errorf("%s: %q read as %+v, alias %t", path, c.Name, parsed, parsed.IsAlias())
			}
		}
	}
}

// A request's none reads as off (§6.3), while a name never carries none: it is a label, a floor and an egress mode.
// An empty request effort asks for none in particular.
func TestInferEffortNoneReadsOff(t *testing.T) {
	effort, err := ParseInferRequestEffort("none")
	if err != nil || effort != InferEffortOff {
		t.Fatalf("a request's none read as %q, %v", effort, err)
	}
	if _, err := ParseInferEffort("none"); !errors.Is(err, ErrInferEffortUnknown) {
		t.Fatalf("a name's none read as an effort: %v", err)
	}
	if effort, err := ParseInferRequestEffort(""); err != nil || effort != "" {
		t.Fatalf("an empty request effort read as %q, %v", effort, err)
	}
	for _, effort := range inferEffortOrder {
		if parsed, err := ParseInferEffort(string(effort)); err != nil || parsed != effort {
			t.Errorf("%s read as %q, %v", effort, parsed, err)
		}
		if parsed, err := ParseInferRequestEffort(string(effort)); err != nil || parsed != effort {
			t.Errorf("a request's %s read as %q, %v", effort, parsed, err)
		}
	}
	for _, word := range []string{"NONE", "None", "Off", "ultra", " high", "high ", "medium-high"} {
		if _, err := ParseInferRequestEffort(word); !errors.Is(err, ErrInferEffortUnknown) {
			t.Errorf("a request's %q read as an effort", word)
		}
	}
}

// The nearest listed effort on §6.3's order, the lower of two equally near.
func TestInferNearestEffort(t *testing.T) {
	listed := []InferEffort{InferEffortOff, InferEffortLow, InferEffortHigh, InferEffortMax}
	cases := []struct {
		asked InferEffort
		want  InferEffort
	}{
		{asked: InferEffortOff, want: InferEffortOff},
		{asked: InferEffortMinimal, want: InferEffortOff},
		{asked: InferEffortLow, want: InferEffortLow},
		{asked: InferEffortMedium, want: InferEffortLow},
		{asked: InferEffortHigh, want: InferEffortHigh},
		{asked: InferEffortXhigh, want: InferEffortHigh},
		{asked: InferEffortMax, want: InferEffortMax},
	}
	for _, c := range cases {
		if got := inferNearestEffort(c.asked, listed); got != c.want {
			t.Errorf("%s mapped to %s, want %s", c.asked, got, c.want)
		}
	}
	if got := inferNearestEffort(InferEffortMax, []InferEffort{InferEffortOff}); got != InferEffortOff {
		t.Errorf("max on a model without reasoning mapped to %s", got)
	}
	if got := inferNearestEffort(InferEffortOff, []InferEffort{InferEffortXhigh, InferEffortHigh}); got != InferEffortHigh {
		t.Errorf("off mapped to %s, want the nearest, high", got)
	}
	if got := inferNearestEffort("ultra", listed); got != "" {
		t.Errorf("an unknown effort mapped to %s", got)
	}
	if got := inferNearestEffort(InferEffortHigh, nil); got != "" {
		t.Errorf("an empty list mapped to %s", got)
	}
}

// A model labeled none loses every TEE mark word from its name, so the name claims nothing its label denies
// (Q-PROV-8); a TEE label keeps the provider's own marks, and a word that only holds the letters is no mark.
func TestInferTeeMarkDroppedForNone(t *testing.T) {
	settings := DefaultInferSettings()
	cases := []struct {
		id    string
		label ComputeLabel
		want  string
	}{
		{id: "glm-5.2-tee", label: ComputeLabelNone, want: "glm-5.2"},
		{id: "GLM-5.2-TEE", label: ComputeLabelNone, want: "glm-5.2"},
		{id: "TDX Llama 4", label: ComputeLabelNone, want: "llama-4"},
		{id: "vendor/Confidential-Model-9b", label: ComputeLabelNone, want: "model-9b"},
		{id: "model-tee-tdx-confidential-x", label: ComputeLabelNone, want: "model-x"},
		{id: "teemo-7b", label: ComputeLabelNone, want: "teemo-7b"},
		{id: "model-tee.v2", label: ComputeLabelNone, want: "model-tee.v2"},
		{id: "glm-5.2-tee", label: ComputeLabelAp, want: "glm-5.2-tee"},
		{id: "glm-5.2-tdx", label: ComputeLabelA1, want: "glm-5.2-tdx"},
		{id: "glm-5.2-confidential", label: ComputeLabelA2, want: "glm-5.2-confidential"},
	}
	for _, c := range cases {
		results, err := InferNormalizeModelId("example", []*InferProviderModel{{Id: c.id, Label: c.label}}, settings)
		if err != nil {
			t.Fatal(err)
		}
		if results[0].Model != c.want || results[0].Refused != "" {
			t.Errorf("%q labeled %s made %q (refused %q), want %q", c.id, c.label, results[0].Model, results[0].Refused, c.want)
		}
	}
	for _, id := range []string{"TEE", "tee-tdx", "Confidential"} {
		results, err := InferNormalizeModelId("example", []*InferProviderModel{{Id: id, Label: ComputeLabelNone}}, settings)
		if err != nil {
			t.Fatal(err)
		}
		if results[0].Model != "" || results[0].Refused == "" {
			t.Errorf("%q, nothing but a mark, made %q", id, results[0].Model)
		}
	}
}

// The normalizer bounds its work: an id past its length is refused, never cut, a name past NameMaxByteCount makes no
// model part, too many ids refuse the call, and a provider that is no slug refuses it too.
func TestInferNormalizeModelIdBounded(t *testing.T) {
	settings := DefaultInferSettings()
	long := strings.Repeat("a", settings.ProviderModelIdMaxByteCount+1)
	fits := strings.Repeat("b", settings.NameMaxByteCount-len("p--minimal"))
	tooLongForAName := fits + "c"
	results, err := InferNormalizeModelId("p", []*InferProviderModel{
		{Id: long, Label: ComputeLabelNone},
		{Id: fits, Label: ComputeLabelNone},
		{Id: tooLongForAName, Label: ComputeLabelNone},
		nil,
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Refused == "" || results[0].Model != "" {
		t.Errorf("an id past its bound made %q", results[0].Model)
	}
	if results[1].Model != fits {
		t.Errorf("an id whose names fit made %q, refused %q", results[1].Model, results[1].Refused)
	}
	if results[2].Refused == "" || results[2].Model != "" {
		t.Errorf("an id whose names pass the bound made %q", results[2].Model)
	}
	if results[3].Refused == "" {
		t.Errorf("a nil id was not refused")
	}
	if _, err := InferParseModelName("p-"+fits+"-minimal", settings); err != nil {
		t.Errorf("the longest name the bound allows was refused: %v", err)
	}

	// a hostile catalog of the most ids, every one colliding with every other, is answered id by id
	colliding := make([]*InferProviderModel, settings.ProviderModelIdMaxCount)
	for i := range colliding {
		colliding[i] = &InferProviderModel{Id: "org" + strings.Repeat("x", i%7) + "/Same-Model", Label: ComputeLabelNone}
		if i%2 == 0 {
			colliding[i].Id = "same-model"
		}
	}
	collided, err := InferNormalizeModelId("p", colliding, settings)
	if err != nil {
		t.Fatal(err)
	}
	for i, result := range collided {
		if !result.Collides || result.Model == "" {
			t.Fatalf("id %d of a catalog that all collides: %+v", i, result)
		}
	}

	tooMany := make([]*InferProviderModel, settings.ProviderModelIdMaxCount+1)
	for i := range tooMany {
		tooMany[i] = &InferProviderModel{Id: "m", Label: ComputeLabelNone}
	}
	if _, err := InferNormalizeModelId("p", tooMany, settings); !errors.Is(err, ErrInferNormalizeTooMany) {
		t.Errorf("too many ids: %v", err)
	}
	for _, provider := range []string{"", "Chutes", "chutes-ai", "chutes.v2", "chutes/x"} {
		if _, err := InferNormalizeModelId(provider, nil, settings); !errors.Is(err, ErrInferProviderInvalid) {
			t.Errorf("provider %q: %v", provider, err)
		}
	}
}

// The parser is total and bounded: past NameMaxByteCount it refuses before reading, and over a deterministic sweep of
// byte strings it never panics, answers exactly one of a reading and an error, and every reading writes back to the
// name it read, so no two names share a reading.
func TestInferParseModelNameTotalAndBounded(t *testing.T) {
	settings := DefaultInferSettings()
	fits := "p-" + strings.Repeat("m", settings.NameMaxByteCount-len("p--off")) + "-off"
	if len(fits) != settings.NameMaxByteCount {
		t.Fatalf("the test's name is %d bytes", len(fits))
	}
	if _, err := InferParseModelName(fits, settings); err != nil {
		t.Fatalf("a name of the bound's length was refused: %v", err)
	}
	if _, err := InferParseModelName(fits+"f", settings); !errors.Is(err, ErrInferModelNameInvalid) {
		t.Fatalf("a name past the bound was read: %v", err)
	}
	if _, err := InferParseModelName(strings.Repeat("\xff", 1024*1024), settings); !errors.Is(err, ErrInferModelNameInvalid) {
		t.Fatalf("a megabyte of garbage was read: %v", err)
	}
	none := DefaultInferSettings()
	none.NameMaxByteCount = 0
	if _, err := InferParseModelName("local-gemma-off", none); !errors.Is(err, ErrInferModelNameInvalid) {
		t.Fatalf("a non-positive bound read a name: %v", err)
	}

	// a fixed linear congruential sweep over an alphabet that makes every case: hyphens, dots, effort words' letters,
	// capitals, slashes and bytes past ASCII
	alphabet := []byte("-.-.-abcdefhilmnortxz019Az/_ \xc3\xa9\xff")
	state := uint64(0x5eed)
	next := func() uint64 {
		state = state*6364136223846793005 + 1442695040888963407
		return state >> 33
	}
	readings := map[string]string{}
	for i := 0; i < 20000; i += 1 {
		length := int(next() % 24)
		name := make([]byte, length)
		for j := range name {
			name[j] = alphabet[next()%uint64(len(alphabet))]
		}
		parsed, err := InferParseModelName(string(name), settings)
		if (parsed == nil) == (err == nil) {
			t.Fatalf("%q: a reading %+v and an error %v", name, parsed, err)
		}
		if parsed == nil {
			continue
		}
		if parsed.String() != string(name) {
			t.Fatalf("%q read as %+v, which writes %q", name, parsed, parsed.String())
		}
		key := parsed.Provider + "\x00" + parsed.Model + "\x00" + string(parsed.Effort)
		if other, ok := readings[key]; ok && other != string(name) {
			t.Fatalf("%q and %q share a reading", name, other)
		}
		readings[key] = string(name)
	}
	if len(readings) == 0 {
		t.Fatal("the sweep read no name")
	}
}

// Search ids sit outside the model namespace (§6.3, §21): search/<engine>/<kind> parses only as a search id, and no
// model name parses as one.
func TestInferSearchIdsOutsideNamespace(t *testing.T) {
	settings := DefaultInferSettings()
	id, err := InferParseSearchId("search/parallel/fast", settings)
	if err != nil || id.Engine != "parallel" || id.Kind != "fast" || id.String() != "search/parallel/fast" {
		t.Fatalf("search/parallel/fast read as %+v, %v", id, err)
	}
	if _, err := InferParseModelName("search/parallel/fast", settings); !errors.Is(err, ErrInferModelNameInvalid) {
		t.Fatalf("a search id read as a model name: %v", err)
	}
	for _, bad := range []string{
		"parallel-fast-high", "search-parallel-fast", "search/parallel", "search/parallel/", "search//fast",
		"search/Parallel/fast", "search/parallel/fast/more", "search/para-llel/fast", "search/parallel/-fast",
		"Search/parallel/fast", "/search/parallel/fast", "search/parallel/fa st",
		"search/parallel/" + strings.Repeat("k", settings.NameMaxByteCount),
	} {
		if _, err := InferParseSearchId(bad, settings); !errors.Is(err, ErrInferSearchIdInvalid) {
			t.Errorf("%q read as a search id: %v", bad, err)
		}
	}
	for _, kind := range []string{"turbo", "basic", "advanced", "deep-research", "v2.1"} {
		if _, err := InferParseSearchId("search/parallel/"+kind, settings); err != nil {
			t.Errorf("the kind %q refused: %v", kind, err)
		}
	}
}
