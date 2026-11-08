// FS-72's descriptor lint: format 1's reserved numbers, read from evs.proto's descriptors, equal
// testdata/evs/reserved_numbers.yml, the decided list (§11.6's kinds row, D-PHASE-9), with none for keep-last-n, which
// descriptor_test.go's TestNoNumberForKeepLastN holds. That format-1 code refuses, ignores or keeps each is the
// code's to prove, with EVS1's and EVS2-M2-01's tasks. This is an external test because the YAML reader is no import
// protocol may take (§4.4), and a list read strictly fails on any key it does not know.

package protocol_test

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

const testReservedNumbersPath = "../testdata/evs/reserved_numbers.yml"

// The list's sections, as reserved_numbers.yml's header gives them.
type testReservedList struct {
	Held    map[string][]int32 `yaml:"held"`
	Fields  map[string]int32   `yaml:"fields"`
	Values  map[string]int32   `yaml:"values"`
	Ignored []string           `yaml:"ignored"`
	Kept    []string           `yaml:"kept"`
	Layouts map[string]int32   `yaml:"layouts"`
}

// The list, read strictly, and evs.proto's descriptors.
func testReservedListAndFile(t *testing.T) (*testReservedList, protoreflect.FileDescriptor) {
	data, err := os.ReadFile(testReservedNumbersPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	list := &testReservedList{}
	if err := decoder.Decode(list); err != nil {
		t.Fatalf("%s: %v", testReservedNumbersPath, err)
	}
	file, err := protoregistry.GlobalFiles.FindFileByPath("protocol/evs.proto")
	if err != nil {
		t.Fatal(err)
	}
	return list, file
}

// A dotted entry's two names.
func testCutEntry(t *testing.T, entry string) (string, string) {
	declaration, name, found := strings.Cut(entry, ".")
	if !found || strings.Contains(name, ".") {
		t.Fatalf("%s is not Declaration.name", entry)
	}
	return declaration, name
}

// Every number a message reserves, the end of each range excluded.
func testHeldFieldNumbers(ranges protoreflect.FieldRanges) []int32 {
	numbers := []int32{}
	for i := range ranges.Len() {
		for number := ranges.Get(i)[0]; number < ranges.Get(i)[1]; number++ {
			numbers = append(numbers, int32(number))
		}
	}
	return numbers
}

// Every number an enum reserves, the end of each range included.
func testHeldValueNumbers(ranges protoreflect.EnumRanges) []int32 {
	numbers := []int32{}
	for i := range ranges.Len() {
		for number := ranges.Get(i)[0]; number <= ranges.Get(i)[1]; number++ {
			numbers = append(numbers, int32(number))
		}
	}
	return numbers
}

// Both directions: a declaration reserves exactly what held lists for it, nothing when it is not listed, and no
// name; and each held entry is a declaration of evs.proto.
func TestEvsReservesOnlyTheListedNumbers(t *testing.T) {
	list, file := testReservedListAndFile(t)
	declared := map[string]bool{}
	check := func(name string, got []int32, reservedNames protoreflect.Names) {
		declared[name] = true
		want := slices.Clone(list.Held[name])
		if want == nil {
			want = []int32{}
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s reserves %v, and the list %v", name, got, want)
		}
		if reservedNames.Len() != 0 {
			t.Errorf("%s reserves a name", name)
		}
	}
	for i := range file.Messages().Len() {
		message := file.Messages().Get(i)
		if message.Messages().Len() != 0 || message.Enums().Len() != 0 {
			t.Errorf("%s nests a declaration, which this lint does not walk", message.Name())
		}
		check(string(message.Name()), testHeldFieldNumbers(message.ReservedRanges()), message.ReservedNames())
	}
	for i := range file.Enums().Len() {
		enum := file.Enums().Get(i)
		check(string(enum.Name()), testHeldValueNumbers(enum.ReservedRanges()), enum.ReservedNames())
	}
	for _, name := range slices.Sorted(maps.Keys(list.Held)) {
		if !declared[name] {
			t.Errorf("held names %s, which evs.proto does not declare", name)
		}
	}
}

// Declared, never left out: format 1 parses each and refuses it as needing format 2, so a field dropped here would
// arrive as an unknown field and pass.
func TestEvsDeclaresTheListedFields(t *testing.T) {
	list, file := testReservedListAndFile(t)
	for _, entry := range slices.Sorted(maps.Keys(list.Fields)) {
		messageName, fieldName := testCutEntry(t, entry)
		message := file.Messages().ByName(protoreflect.Name(messageName))
		if message == nil {
			t.Errorf("%s: evs.proto declares no message %s", entry, messageName)
			continue
		}
		field := message.Fields().ByName(protoreflect.Name(fieldName))
		if field == nil {
			t.Errorf("%s is missing", entry)
			continue
		}
		if int32(field.Number()) != list.Fields[entry] {
			t.Errorf("%s is %d, and the list %d", entry, field.Number(), list.Fields[entry])
		}
	}
}

// The values format 1 refuses or ignores, by their numbers. EvsPush.flags, EvsEntryVersion.versioning and
// EvsLocator.kind are uint32 on the wire, so their enums are the only place those numbers can drift.
func TestEvsDeclaresTheListedValues(t *testing.T) {
	list, file := testReservedListAndFile(t)
	for _, entry := range slices.Sorted(maps.Keys(list.Values)) {
		enumName, valueName := testCutEntry(t, entry)
		enum := file.Enums().ByName(protoreflect.Name(enumName))
		if enum == nil {
			t.Errorf("%s: evs.proto declares no enum %s", entry, enumName)
			continue
		}
		value := enum.Values().ByName(protoreflect.Name(valueName))
		if value == nil {
			t.Errorf("%s is missing", entry)
			continue
		}
		if int32(value.Number()) != list.Values[entry] {
			t.Errorf("%s is %d, and the list %d", entry, value.Number(), list.Values[entry])
		}
	}
}

// What §11.6's kinds row and D-PHASE-9 write by name is on the list, so the list can lose none of it, and ignored and
// kept each name a listed number once.
func TestEvsListHoldsTheDecidedReservations(t *testing.T) {
	list, _ := testReservedListAndFile(t)
	for _, entry := range []string{
		"EvsPush.drop_sha256", "EvsPush.index_epoch", "EvsHead.index_epoch", "EvsEntryVersion.versioning",
		"EvsLocator.staged", "EvsUploadReceipt.versionless", "EvsProvenance.tainted", "EvsReadPathReply.state",
	} {
		if _, listed := list.Fields[entry]; !listed {
			t.Errorf("the design reserves %s, and the list leaves it out", entry)
		}
	}
	for _, entry := range []string{
		"EvsPushFlag.EVS_PUSH_DROP", "EvsPushFlag.EVS_PUSH_CUT", "EvsLocatorKind.EVS_LOCATOR_VERSIONLESS_SEGMENT",
		"EvsVersioning.EVS_VERSIONING_VERSIONLESS", "EvsVersioning.EVS_VERSIONING_INDEX",
		"EvsWindowFlag.EVS_WINDOW_VERSIONLESS_REPLACED", "EvsWindowFlag.EVS_WINDOW_DROP",
		"EvsReadPathState.EVS_READ_PATH_DROP_PENDING", "EvsReadPathState.EVS_READ_PATH_DROPPED",
	} {
		if _, listed := list.Values[entry]; !listed {
			t.Errorf("the design reserves %s, and the list leaves it out", entry)
		}
	}
	for _, layout := range []string{"batch header format", "segment header format", "repo/ format"} {
		if list.Layouts[layout] != 2 {
			t.Errorf("the design reserves %s 2, and the list gives %d", layout, list.Layouts[layout])
		}
	}
	seen := map[string]string{}
	for section, entries := range map[string][]string{"ignored": list.Ignored, "kept": list.Kept} {
		for _, entry := range entries {
			_, isField := list.Fields[entry]
			_, isValue := list.Values[entry]
			if !isField && !isValue {
				t.Errorf("%s names %s, which fields and values do not list", section, entry)
			}
			if other, twice := seen[entry]; twice {
				t.Errorf("%s is under both %s and %s", entry, other, section)
			}
			seen[entry] = section
		}
	}
}
