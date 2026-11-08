// I-18 for gkm.proto: every field, by number and type, names the §2.8 row that shows it. Most of that file has no design
// fence, so this map is also what pins its numbers and types. It is an area's metadata_rows.yml, the form §22.7's guard
// reads.

package sidecartest

import (
	"bytes"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"gopkg.in/yaml.v3"

	_ "github.com/urnetwork/sidecar/protocol"
)

const (
	testGkmProtoPath = "protocol/gkm.proto"
	testGkmRowsPath  = "../testdata/gkm/metadata_rows.yml"
)

// Live gkm rows no field names, with why. A row here that a field does name fails, so this cannot go stale.
var testGkmRowsWithoutFields = map[string]string{
	"gkm-6": "an external commit is GkmEpochObject.commit again, framed as PublicMessage, which gkm-2 names",
	"gkm-9": "the service log, which no message carries",
}

// One line of metadata_rows.yml, the form schemaGuardAreaField reads. Exactly one of Sees and Pending is set.
type testGkmField struct {
	Number  int32  `yaml:"number"`
	Type    string `yaml:"type"`
	Row     string `yaml:"row"`
	Sees    string `yaml:"sees"`
	Pending string `yaml:"pending"`
	Until   string `yaml:"until"`
}

// metadata_rows.yml by Message.field, read as strictly as the list it points into: a duplicate, an unknown key or a line
// that is neither sees nor pending stops the test.
func testGkmFields(t *testing.T) map[string]testGkmField {
	source, err := os.ReadFile(testGkmRowsPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	decoder.KnownFields(true)
	fields := map[string]testGkmField{}
	if err := decoder.Decode(&fields); err != nil {
		t.Fatalf("%s: %v", testGkmRowsPath, err)
	}
	for name, field := range fields {
		if (field.Sees == "") == (field.Pending == "") {
			t.Fatalf("%s needs exactly one of sees and pending", name)
		}
	}
	return fields
}

// The real list. A failure here is §2.8's, or a checkout without it, and neither is a pass.
func testGkmMetadataList(t *testing.T) *MetadataList {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// D-KEYS-10: no field is removed after M2's entry review. Every field of every message is listed with its number and
// type, and nothing is listed that is not a field, so a change to the wire is a change to that list too, and a new field
// cannot land without naming its row.
func TestGkmFieldsMatchTheirDescriptors(t *testing.T) {
	file, err := protoregistry.GlobalFiles.FindFileByPath(testGkmProtoPath)
	if err != nil {
		t.Fatal(err)
	}
	fieldType := func(field protoreflect.FieldDescriptor) string {
		name := field.Kind().String()
		switch field.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			name = string(field.Message().Name())
		case protoreflect.EnumKind:
			name = string(field.Enum().Name())
		}
		if field.IsList() {
			return "repeated " + name
		}
		return name
	}
	listed := testGkmFields(t)
	declared := map[string]bool{}
	messages := file.Messages()
	for i := range messages.Len() {
		message := messages.Get(i)
		fields := message.Fields()
		if fields.Len() == 0 {
			t.Errorf("%s has no field", message.Name())
		}
		for j := range fields.Len() {
			field := fields.Get(j)
			name := string(message.Name()) + "." + string(field.Name())
			declared[name] = true
			want, ok := listed[name]
			if !ok {
				t.Errorf("%s is not in %s", name, testGkmRowsPath)
				continue
			}
			if int32(field.Number()) != want.Number {
				t.Errorf("%s is %d, and the list writes %d", name, field.Number(), want.Number)
			}
			if got := fieldType(field); got != want.Type {
				t.Errorf("%s is %s, and the list writes %s", name, got, want.Type)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(listed)) {
		if !declared[name] {
			t.Errorf("%s is listed and is no field", name)
		}
	}
}

// I-18: each field names a live row, and what it quotes is still in it. Pending fields are logged, so a run shows what
// waits on §2.8's wording.
func TestGkmFieldsNameLiveRows(t *testing.T) {
	list := testGkmMetadataList(t)
	listed := testGkmFields(t)
	for _, name := range slices.Sorted(maps.Keys(listed)) {
		field := listed[name]
		row := list.Row(field.Row)
		if row == nil || !row.Live() {
			t.Errorf("%s names %s, which is withdrawn or no row", name, field.Row)
			continue
		}
		if field.Pending != "" {
			t.Logf("%s waits on %s: %s", name, field.Row, field.Pending)
			continue
		}
		if !strings.Contains(row.Sees, field.Sees) {
			t.Errorf("%s: %s does not say %q", name, field.Row, field.Sees)
		}
	}
}

// And back: a gkm row no field names is a row this file stopped backing.
func TestGkmRowsAreBacked(t *testing.T) {
	named := map[string]bool{}
	for _, field := range testGkmFields(t) {
		named[field.Row] = true
	}
	for _, row := range testGkmMetadataList(t).LiveRows() {
		if !strings.HasPrefix(row.Id, "gkm-") {
			continue
		}
		if _, excused := testGkmRowsWithoutFields[row.Id]; named[row.Id] == excused {
			t.Errorf("%s: named by a field is %t, and excused is %t", row.Id, named[row.Id], excused)
		}
	}
}
