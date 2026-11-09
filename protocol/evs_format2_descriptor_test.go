// Format 2's descriptor lint (EVS2-M10-01): testdata/evs/format2/schema.yml's messages, enums and the format-1 numbers
// format 2 relies on, read from evs.proto's descriptors, so format 2's chapter adds and moves nothing format 1 declared
// at M2; none of its names serves keep-last-n (owner decisions 165, 167); each new message round-trips, proto.Equal;
// and testdata/evs/format2/metadata_rows.yml is complete against the descriptor, a format-2 field with no line failing
// here before §22.7's guard reads it (I-18). §22.6's body seeds for the new messages are TestEveryEvsBodyHasItsSeeds',
// which walks every evs message. External, as evs_reserved_test.go is, because the YAML reader is no import protocol
// may take (§4.4).

package protocol_test

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar/protocol"
)

const (
	testFormat2SchemaPath       = "../testdata/evs/format2/schema.yml"
	testFormat2MetadataRowsPath = "../testdata/evs/format2/metadata_rows.yml"
)

// The schema's sections, as schema.yml's header gives them.
type testFormat2Schema struct {
	Messages map[string][]string          `yaml:"messages"`
	Enums    map[string][]string          `yaml:"enums"`
	ReliesOn map[string]int32             `yaml:"relies_on"`
	Layouts  map[string]int64             `yaml:"layouts"`
	Vectors  map[string]map[string]string `yaml:"vectors"`
}

// One line of an area's metadata_rows.yml, as §22.7's guard reads it.
type testFormat2MetadataRow struct {
	Number  int32  `yaml:"number"`
	Type    string `yaml:"type"`
	Row     string `yaml:"row"`
	Sees    string `yaml:"sees"`
	Pending string `yaml:"pending"`
	Until   string `yaml:"until"`
}

// A YAML file read strictly into value.
func testReadStrictYaml(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(value); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// The schema and evs.proto's descriptors.
func testFormat2SchemaAndFile(t *testing.T) (*testFormat2Schema, protoreflect.FileDescriptor) {
	schema := &testFormat2Schema{}
	testReadStrictYaml(t, testFormat2SchemaPath, schema)
	file, err := protoregistry.GlobalFiles.FindFileByPath("protocol/evs.proto")
	if err != nil {
		t.Fatal(err)
	}
	return schema, file
}

// A field as "number name type", repeated and message or enum types by name.
func testFormat2FieldLine(field protoreflect.FieldDescriptor) string {
	return fmt.Sprintf("%d %s %s", field.Number(), field.Name(), testFormat2FieldType(field))
}

// A field's type as a .proto writes it.
func testFormat2FieldType(field protoreflect.FieldDescriptor) string {
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

// Each format-2 message is declared with exactly the schema's fields, in order, holding no oneof (§22.5's lint) and
// nesting nothing.
func TestEvsFormat2MessagesKeepTheirNumbers(t *testing.T) {
	schema, file := testFormat2SchemaAndFile(t)
	if len(schema.Messages) == 0 {
		t.Fatal("the schema lists no message")
	}
	for _, name := range slices.Sorted(maps.Keys(schema.Messages)) {
		message := file.Messages().ByName(protoreflect.Name(name))
		if message == nil {
			t.Errorf("evs.proto declares no %s", name)
			continue
		}
		got := []string{}
		for i := range message.Fields().Len() {
			got = append(got, testFormat2FieldLine(message.Fields().Get(i)))
		}
		if !slices.Equal(got, schema.Messages[name]) {
			t.Errorf("%s:\n got %q\nwant %q", name, got, schema.Messages[name])
		}
		if message.Oneofs().Len() != 0 || message.Messages().Len() != 0 || message.Enums().Len() != 0 {
			t.Errorf("%s holds a oneof or nests a declaration", name)
		}
		if message.ReservedRanges().Len() != 0 || message.ReservedNames().Len() != 0 {
			t.Errorf("%s reserves, which nothing in format 2 asks for", name)
		}
	}
}

// Each format-2 enum is declared with exactly the schema's values, in order, starting at a zero value.
func TestEvsFormat2EnumsKeepTheirNumbers(t *testing.T) {
	schema, file := testFormat2SchemaAndFile(t)
	for _, name := range slices.Sorted(maps.Keys(schema.Enums)) {
		enum := file.Enums().ByName(protoreflect.Name(name))
		if enum == nil {
			t.Errorf("evs.proto declares no %s", name)
			continue
		}
		got := []string{}
		for i := range enum.Values().Len() {
			value := enum.Values().Get(i)
			got = append(got, fmt.Sprintf("%d %s", value.Number(), value.Name()))
		}
		if !slices.Equal(got, schema.Enums[name]) {
			t.Errorf("%s:\n got %q\nwant %q", name, got, schema.Enums[name])
		}
		if enum.Values().Len() == 0 || enum.Values().Get(0).Number() != 0 {
			t.Errorf("%s does not start at 0", name)
		}
	}
}

// What format 2 reads of format 1 stays at the numbers format 1 gave it: each relies_on entry is declared at its
// number, and every number testdata/evs/reserved_numbers.yml lists for format 2 is among them, so the two lists cannot
// drift apart.
func TestEvsFormat2RelyOnFormat1sNumbers(t *testing.T) {
	schema, file := testFormat2SchemaAndFile(t)
	for _, entry := range slices.Sorted(maps.Keys(schema.ReliesOn)) {
		declaration, name, found := strings.Cut(entry, ".")
		if !found {
			t.Errorf("%s is not Declaration.name", entry)
			continue
		}
		if message := file.Messages().ByName(protoreflect.Name(declaration)); message != nil {
			field := message.Fields().ByName(protoreflect.Name(name))
			if field == nil || int32(field.Number()) != schema.ReliesOn[entry] {
				t.Errorf("%s moved or went: the schema says %d", entry, schema.ReliesOn[entry])
			}
			continue
		}
		if enum := file.Enums().ByName(protoreflect.Name(declaration)); enum != nil {
			value := enum.Values().ByName(protoreflect.Name(name))
			if value == nil || int32(value.Number()) != schema.ReliesOn[entry] {
				t.Errorf("%s moved or went: the schema says %d", entry, schema.ReliesOn[entry])
			}
			continue
		}
		t.Errorf("%s: evs.proto declares no %s", entry, declaration)
	}

	reserved := &struct {
		Held    map[string][]int32 `yaml:"held"`
		Fields  map[string]int32   `yaml:"fields"`
		Values  map[string]int32   `yaml:"values"`
		Ignored []string           `yaml:"ignored"`
		Kept    []string           `yaml:"kept"`
		Layouts map[string]int32   `yaml:"layouts"`
	}{}
	testReadStrictYaml(t, "../testdata/evs/reserved_numbers.yml", reserved)
	for _, listed := range []map[string]int32{reserved.Fields, reserved.Values} {
		for entry, number := range listed {
			if relied, found := schema.ReliesOn[entry]; !found || relied != number {
				t.Errorf("reserved_numbers.yml lists %s at %d, and the schema relies on %d", entry, number, relied)
			}
		}
	}
	for layout, number := range reserved.Layouts {
		if schema.Layouts[layout] != int64(number) {
			t.Errorf("reserved_numbers.yml reserves %s %d, and the schema's layouts say %d", layout, number, schema.Layouts[layout])
		}
	}
}

// Every name format 2 adds keeps clear of keep-last-n, which no number serves (owner decisions 165, 167).
func TestEvsFormat2NamesNoKeepLastN(t *testing.T) {
	schema, _ := testFormat2SchemaAndFile(t)
	names := slices.Collect(maps.Keys(schema.Messages))
	names = append(names, slices.Collect(maps.Keys(schema.Enums))...)
	for _, lines := range schema.Messages {
		names = append(names, lines...)
	}
	for _, lines := range schema.Enums {
		names = append(names, lines...)
	}
	for _, name := range names {
		folded := strings.ToLower(strings.NewReplacer("_", "", " ", "", "-", "").Replace(name))
		if strings.Contains(folded, "keeplast") || strings.Contains(folded, "lastn") {
			t.Errorf("%q serves keep-last-n", name)
		}
	}
}

// The format-2 fields of format-1 messages: those the reserved list holds that no format-1 file maps, which the
// format-2 area file must map.
var testFormat2AddedFields = []string{"EvsReadPathReply.drop_statement", "EvsReadPathReply.drop_body"}

// metadata_rows.yml complete against the descriptor (I-18): every field of every format-2 message, and every format-2
// field added to a format-1 message, has exactly one line, whose number and type are the descriptor's, naming a row
// with words of it or saying why not yet; and every line names a field format 2 declares.
func TestEvsFormat2MetadataRowsComplete(t *testing.T) {
	schema, file := testFormat2SchemaAndFile(t)
	rows := map[string]*testFormat2MetadataRow{}
	testReadStrictYaml(t, testFormat2MetadataRowsPath, &rows)
	want := map[string]protoreflect.FieldDescriptor{}
	for name := range schema.Messages {
		message := file.Messages().ByName(protoreflect.Name(name))
		if message == nil {
			t.Fatalf("evs.proto declares no %s", name)
		}
		for i := range message.Fields().Len() {
			field := message.Fields().Get(i)
			want[name+"."+string(field.Name())] = field
		}
	}
	for _, key := range testFormat2AddedFields {
		messageName, fieldName, _ := strings.Cut(key, ".")
		field := file.Messages().ByName(protoreflect.Name(messageName)).Fields().ByName(protoreflect.Name(fieldName))
		if field == nil {
			t.Fatalf("evs.proto declares no %s", key)
		}
		want[key] = field
	}
	for _, key := range slices.Sorted(maps.Keys(want)) {
		row := rows[key]
		if row == nil {
			t.Errorf("%s has no line: give it its §2.8 row, and if §2.8 has none raise a question (I-18)", key)
			continue
		}
		field := want[key]
		if row.Number != int32(field.Number()) || row.Type != testFormat2FieldType(field) {
			t.Errorf("%s is %d %s, and its line says %d %s", key, field.Number(), testFormat2FieldType(field), row.Number, row.Type)
		}
		if !strings.HasPrefix(row.Row, "evs-") || (row.Sees == "") == (row.Pending == "") {
			t.Errorf("%s: a line names an evs row and exactly one of sees and pending", key)
		}
		if row.Pending != "" && row.Until != "M10" {
			t.Errorf("%s is pending until %q, and format 2's rows are due by M10's exit", key, row.Until)
		}
	}
	for key := range rows {
		if _, ok := want[key]; !ok {
			t.Errorf("%s has a line and is no format-2 field", key)
		}
	}
}

// Each format-2 message, every field set, round-trips through its deterministic encoding, proto.Equal, and re-encodes
// to the same bytes; the reordered, repeated, unknown and non-minimal forms are TestEvsSeedsDecodeAlike's (§22.6).
func TestEvsFormat2MessagesRoundTrip(t *testing.T) {
	id := bytes.Repeat([]byte{0x11}, 16)
	hash := bytes.Repeat([]byte{0x22}, 32)
	dropPath := &protocol.EvsDropPath{
		Lineage:        []*protocol.EvsSourcePath{{Epoch: 3, TokenPath: [][]byte{id}}, {Epoch: 2, TokenPath: [][]byte{id, id}}},
		MapParts:       []uint32{1},
		ThroughVersion: 9,
		Boundary:       1,
		Count:          8,
		ListedSha256:   hash,
	}
	messages := []proto.Message{
		&protocol.EvsPurgeList{
			Candidates: []*protocol.EvsPurgeCandidate{{
				TokenPath: [][]byte{id, id}, ReplacedVersion: 7, SegmentIds: [][]byte{hash},
				StagedSegmentIds: [][]byte{hash, hash}, SlotIds: [][]byte{id},
			}},
		},
		&protocol.EvsPurgeList{Marked: true},
		&protocol.EvsDropsReply{Drops: []*protocol.EvsDropStatus{{
			DropId: id, RefId: id, PushId: id, Version: 12, NotBeforeMs: 1_700_000_000_000,
			State: protocol.EvsDropState_EVS_DROP_EXECUTING, Phase: protocol.EvsDropPhase_EVS_DROP_MARK, Progress: 3,
			ProgressTotal: 9, Reason: protocol.EvsDropRefusal_EVS_DROP_REFUSAL_MISMATCH, FreedBytes: 4096, PreviewId: id,
		}}},
		&protocol.EvsDropPreviewRequest{RefId: id, Paths: []*protocol.EvsDropPath{dropPath, dropPath}},
		&protocol.EvsDropPreviewReply{
			PreviewId: id, State: protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE, Progress: 30, ProgressTotal: 30,
			Paths:      []*protocol.EvsDropPreviewPath{{ListMatch: true, Count: 8}, {Count: 2}},
			FreedBytes: 1, SharedBytes: 2, InlineBytes: 3, PackedBytes: 4, YoungBytes: 5, SnapshotVersion: 40,
			SnapshotMs: 1_700_000_000_000,
		},
		&protocol.EvsReadPathReply{
			State: protocol.EvsReadPathState_EVS_READ_PATH_DROPPED, DropId: id, DropVersion: 9,
			DropStatement: hash, DropBody: hash,
		},
	}
	for _, message := range messages {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		decoded := message.ProtoReflect().Type().New().Interface()
		if err := proto.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("%T: %v", message, err)
		}
		if !proto.Equal(message, decoded) {
			t.Errorf("%T decoded as another value", message)
		}
		again, err := proto.MarshalOptions{Deterministic: true}.Marshal(decoded)
		if err != nil || !bytes.Equal(again, encoded) {
			t.Errorf("%T re-encodes to other bytes", message)
		}
	}
}
