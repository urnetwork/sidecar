//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"maps"
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// support/registry.yml as this test reads it, strictly.
type testSupportLogRegistryFile struct {
	Version int `yaml:"version"`
	Buckets struct {
		Count    []*testSupportLogRegistryBucket `yaml:"count"`
		Duration []*testSupportLogRegistryBucket `yaml:"duration"`
		Size     []*testSupportLogRegistryBucket `yaml:"size"`
	} `yaml:"buckets"`
	Components []*struct {
		Name   string `yaml:"name"`
		Number int    `yaml:"number"`
	} `yaml:"components"`
	Enums  map[string][]string `yaml:"enums"`
	Fields []*struct {
		Name   string `yaml:"name"`
		Number int    `yaml:"number"`
		Type   string `yaml:"type"`
		Enum   string `yaml:"enum"`
		Object string `yaml:"object"`
	} `yaml:"fields"`
	Codes []*struct {
		Component string   `yaml:"component"`
		Code      string   `yaml:"code"`
		Number    int      `yaml:"number"`
		Severity  string   `yaml:"severity"`
		Fields    []string `yaml:"fields"`
	} `yaml:"codes"`
}

// One bucket as the registry writes it.
type testSupportLogRegistryBucket struct {
	Label string  `yaml:"label"`
	Max   *uint64 `yaml:"max"`
}

// support_log_registry.go holds what support/registry.yml says, every number, name, type and bucket of it: the test
// make check's hygiene rule names for the generated file (check/support_log_test.go generates it and holds its text).
func TestSupportLogRegistryMatchesItsSource(t *testing.T) {
	data, err := os.ReadFile("support/registry.yml")
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	file := &testSupportLogRegistryFile{}
	if err := decoder.Decode(file); err != nil {
		t.Fatal(err)
	}
	registry := supportLogRegistry
	if registry.version != file.Version || SupportLogRegistryVersion != file.Version {
		t.Errorf("version %d here, %d in the file", registry.version, file.Version)
	}
	for _, buckets := range []struct {
		name string
		have []supportLogBucket
		want []*testSupportLogRegistryBucket
	}{
		{name: "count", have: registry.countBuckets, want: file.Buckets.Count},
		{name: "duration", have: registry.durationBuckets, want: file.Buckets.Duration},
		{name: "size", have: registry.sizeBuckets, want: file.Buckets.Size},
	} {
		if len(buckets.have) != len(buckets.want) {
			t.Errorf("%d %s buckets here, %d in the file", len(buckets.have), buckets.name, len(buckets.want))
			continue
		}
		for i, want := range buckets.want {
			have := buckets.have[i]
			if have.label != want.Label || have.bounded != (want.Max != nil) || (want.Max != nil && have.max != *want.Max) {
				t.Errorf("%s bucket %d reads %+v", buckets.name, i, have)
			}
		}
	}
	components := map[string]SupportLogComponent{}
	for _, component := range file.Components {
		components[component.Name] = SupportLogComponent(component.Number)
		if registry.components[SupportLogComponent(component.Number)] != component.Name {
			t.Errorf("component %d reads %q", component.Number, registry.components[SupportLogComponent(component.Number)])
		}
	}
	if len(registry.components) != len(file.Components) {
		t.Errorf("%d components here, %d in the file", len(registry.components), len(file.Components))
	}
	if !maps.EqualFunc(registry.enums, file.Enums, slices.Equal[[]string]) {
		t.Errorf("enums %v here, %v in the file", registry.enums, file.Enums)
	}
	types := map[string]supportLogFieldType{
		"enum": supportLogFieldTypeEnum, "count": supportLogFieldTypeCount, "duration": supportLogFieldTypeDuration,
		"size": supportLogFieldTypeSize, "version": supportLogFieldTypeVersion, "boolean": supportLogFieldTypeBoolean,
		"token": supportLogFieldTypeToken,
	}
	fieldNumbers := map[string]SupportLogFieldNumber{}
	for _, field := range file.Fields {
		fieldNumbers[field.Name] = SupportLogFieldNumber(field.Number)
		row := registry.fields[SupportLogFieldNumber(field.Number)]
		if row == nil || row.name != field.Name || row.fieldType != types[field.Type] || row.enum != field.Enum || row.object != field.Object {
			t.Errorf("field %d reads %+v", field.Number, row)
		}
	}
	if len(registry.fields) != len(file.Fields) {
		t.Errorf("%d fields here, %d in the file", len(registry.fields), len(file.Fields))
	}
	severities := map[string]SupportLogSeverity{"info": SupportLogSeverityInfo, "degraded": SupportLogSeverityDegraded, "failed": SupportLogSeverityFailed}
	for _, code := range file.Codes {
		row := registry.codes[SupportLogCode(code.Number)]
		wantFields := []SupportLogFieldNumber{}
		for _, name := range code.Fields {
			wantFields = append(wantFields, fieldNumbers[name])
		}
		if row == nil || row.component != components[code.Component] || row.name != code.Code || row.severity != severities[code.Severity] ||
			!slices.Equal(row.fields, wantFields) {
			t.Errorf("code %d reads %+v", code.Number, row)
		}
	}
	if len(registry.codes) != len(file.Codes) {
		t.Errorf("%d codes here, %d in the file", len(registry.codes), len(file.Codes))
	}
}
