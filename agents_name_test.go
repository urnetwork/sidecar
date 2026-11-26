//go:build !ios_extension && !sidecar_http

// An agent's name (§20.5): the grammar, the name derived from a task and the suffixed name, on testdata's vectors, and
// every name a valid DESIGN §5.5 label.

package sidecar

import (
	"embed"
	"encoding/json"
	"errors"
	"testing"
)

//go:embed testdata/agents/card
var testAgentsCardFiles embed.FS

// testdata/agents/card/names.json.
type testAgentNameVectors struct {
	Valid   []string `json:"valid"`
	Invalid []string `json:"invalid"`
	Derived []struct {
		Task string `json:"task"`
		Name string `json:"name"`
	} `json:"derived"`
	Suffixed []struct {
		Name   string `json:"name"`
		Suffix int    `json:"suffix"`
		Want   string `json:"want"`
	} `json:"suffixed"`
}

func testAgentNames(t *testing.T) *testAgentNameVectors {
	t.Helper()
	data, err := testAgentsCardFiles.ReadFile("testdata/agents/card/names.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testAgentNameVectors{}
	if err := json.Unmarshal(data, vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestAgentNameGrammar(t *testing.T) {
	settings := DefaultSkillSettings()
	labels := DefaultSidecarAgentLabelSettings()
	vectors := testAgentNames(t)
	for _, text := range vectors.Valid {
		name, err := ParseAgentName(text, settings)
		if err != nil || name.String() != text {
			t.Errorf("%q: %v", text, err)
		}
		// every name is a label as it stands, so the record, the directory and the inbox say one name
		if err := labels.Check(text); err != nil {
			t.Errorf("%q is no label: %v", text, err)
		}
	}
	for _, text := range vectors.Invalid {
		if _, err := ParseAgentName(text, settings); !errors.Is(err, ErrAgentNameInvalid) {
			t.Errorf("%q: %v", text, err)
		}
	}
	// the bound is a setting
	short := DefaultSkillSettings()
	short.NameMaxByteCount = 4
	if _, err := ParseAgentName("abcde", short); !errors.Is(err, ErrAgentNameInvalid) {
		t.Errorf("past a shorter bound: %v", err)
	}
}

func TestAgentNameDerivedAndSuffixed(t *testing.T) {
	settings := DefaultSkillSettings()
	vectors := testAgentNames(t)
	for _, vector := range vectors.Derived {
		name := DeriveAgentName(vector.Task, settings)
		if name.String() != vector.Name {
			t.Errorf("%q derives %q, want %q", vector.Task, name, vector.Name)
		}
		if _, err := ParseAgentName(name.String(), settings); err != nil {
			t.Errorf("%q derives a name out of the grammar: %v", vector.Task, err)
		}
	}
	for _, vector := range vectors.Suffixed {
		name := AgentNameWithSuffix(AgentName(vector.Name), vector.Suffix, settings)
		if name.String() != vector.Want {
			t.Errorf("%q with %d is %q, want %q", vector.Name, vector.Suffix, name, vector.Want)
		}
		if _, err := ParseAgentName(name.String(), settings); err != nil {
			t.Errorf("%q with %d is out of the grammar: %v", vector.Name, vector.Suffix, err)
		}
	}
}
