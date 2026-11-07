// gkm.proto against what §10 and §22 ask of it: every field pinned and naming its §2.8 row (I-18), which is also what
// holds the messages no design fence covers, and §22.6's seeds on disk for every message.

package protocol

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const (
	testGkmProtoPath      = "protocol/gkm.proto"
	testGkmRowsPath       = "../testdata/gkm/metadata_rows.yml"
	testFuzzSeedDirectory = "testdata/fuzz/FuzzBody"

	// How §2.8's fence opens, so the reader below cannot settle on another yaml block.
	testMetadataListHeading = "# metadata_list.yml"
)

// Live gkm rows no field names, with why. A row here that a field does name fails, so this cannot go stale.
var testGkmRowsWithoutFields = map[string]string{
	"gkm-6": "an external commit is GkmEpochObject.commit again, framed as PublicMessage, which gkm-2's line names",
	"gkm-9": "the service log, which no message carries",
}

var testUpdateFuzzSeeds = flag.Bool(
	"update-fuzz-seeds", false, "write gkm.proto's seeds under testdata/fuzz/FuzzBody instead of checking for them",
)

// One line of testdata/gkm/metadata_rows.yml. Exactly one of sees and pending is set.
type testGkmField struct {
	number    int32
	fieldType string
	row       string
	sees      string
	pending   string
}

// testdata/gkm/metadata_rows.yml, by Message.field. A line that does not read stops the test rather than being skipped.
func testGkmFields(t *testing.T) map[string]testGkmField {
	source, err := os.ReadFile(testGkmRowsPath)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(
		`^([A-Za-z]+\.[a-z0-9_]+): \{number: ([0-9]+), type: ([A-Za-z0-9 ]+), row: ([a-z]+-[0-9]+), (sees|pending): "([^"]*)"\}$`,
	)
	fields := map[string]testGkmField{}
	for line := range strings.SplitSeq(string(source), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		match := pattern.FindStringSubmatch(line)
		if match == nil {
			t.Fatalf("a line does not read: %q", line)
		}
		if _, repeated := fields[match[1]]; repeated {
			t.Fatalf("%s is listed twice", match[1])
		}
		number, err := strconv.ParseInt(match[2], 10, 32)
		if err != nil {
			t.Fatalf("%s: %v", match[1], err)
		}
		field := testGkmField{number: int32(number), fieldType: match[3], row: match[4]}
		if match[5] == "sees" {
			field.sees = match[6]
		} else {
			field.pending = match[6]
		}
		fields[match[1]] = field
	}
	return fields
}

// §2.8's rows by id: what each row shows, and nothing for a withdrawn one. metadata_list.yml is that fence copied byte
// for byte, so this reads what it holds, on any branch, whether or not the copy has landed.
func testMetadataRows(t *testing.T) map[string]string {
	design, err := os.ReadFile(testDesignPath)
	if err != nil {
		t.Fatalf("this test needs the design beside the module: %v", err)
	}
	_, afterHeading, found := strings.Cut(string(design), "\n**The list**")
	if !found {
		t.Fatal("no list in the design")
	}
	_, fence, found := strings.Cut(afterHeading, "```yaml\n")
	if !found {
		t.Fatal("no fence after the list's heading")
	}
	fence, _, found = strings.Cut(fence, "\n```")
	if !found || !strings.HasPrefix(fence, testMetadataListHeading) {
		t.Fatalf("the fence does not open as the list: %.40q", fence)
	}
	rowLine := regexp.MustCompile(`^([a-z]+-[0-9]+):$`)
	rows := map[string]string{}
	row := ""
	for line := range strings.SplitSeq(fence, "\n") {
		if match := rowLine.FindStringSubmatch(line); match != nil {
			row = match[1]
			rows[row] = ""
			continue
		}
		if sees, ok := strings.CutPrefix(line, "  sees: "); ok && row != "" {
			rows[row] = sees
		}
	}
	// A reader that found nothing would pass everything that consults it.
	if len(rows) < 90 {
		t.Fatalf("found %d rows, too few to have read the list", len(rows))
	}
	return rows
}

// A descriptor's type as metadata_rows.yml writes it.
func testGkmFieldType(field protoreflect.FieldDescriptor) string {
	fieldType := field.Kind().String()
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		fieldType = string(field.Message().Name())
	case protoreflect.EnumKind:
		fieldType = string(field.Enum().Name())
	}
	if field.IsList() {
		return "repeated " + fieldType
	}
	return fieldType
}

// D-KEYS-10: no field is removed after M2's entry review, and most of this file has no fence. Every field of every
// message is listed with its number and type, and nothing is listed that is not a field, so a change to the wire is a
// change to that list too. A new field cannot land without naming its row.
func TestGkmFieldsMatchTheirDescriptors(t *testing.T) {
	listed := testGkmFields(t)
	messages := testFile(t, testGkmProtoPath).Messages()
	declared := map[string]bool{}
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
			if int32(field.Number()) != want.number {
				t.Errorf("%s is %d, and the list writes %d", name, field.Number(), want.number)
			}
			if got := testGkmFieldType(field); got != want.fieldType {
				t.Errorf("%s is %s, and the list writes %s", name, got, want.fieldType)
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
	rows := testMetadataRows(t)
	listed := testGkmFields(t)
	for _, name := range slices.Sorted(maps.Keys(listed)) {
		field := listed[name]
		sees, ok := rows[field.row]
		if !ok || sees == "" {
			t.Errorf("%s names %s, which is withdrawn or no row", name, field.row)
			continue
		}
		if field.pending != "" {
			t.Logf("%s waits on %s: %s", name, field.row, field.pending)
			continue
		}
		if !strings.Contains(sees, field.sees) {
			t.Errorf("%s: %s does not say %q", name, field.row, field.sees)
		}
	}
}

// And back: a gkm row no field names is a row this file stopped backing.
func TestGkmRowsAreBacked(t *testing.T) {
	rows := testMetadataRows(t)
	named := map[string]bool{}
	for _, field := range testGkmFields(t) {
		named[field.row] = true
	}
	for row, sees := range rows {
		if !strings.HasPrefix(row, "gkm-") || sees == "" {
			continue
		}
		if _, excused := testGkmRowsWithoutFields[row]; named[row] == excused {
			t.Errorf("%s: named by a field is %t, and excused is %t", row, named[row], excused)
		}
	}
}

// §4.7: route bodies are messages, never protobuf service blocks, and no file here declares one.
func TestProtoFilesDeclareNoService(t *testing.T) {
	for _, path := range testProtoFiles {
		if services := testFile(t, path).Services(); services.Len() != 0 {
			t.Errorf("%s declares %s", path, services.Get(0).Name())
		}
	}
}

// §4.7: gkm's wire reaches past itself only into protocol/bridge, for AuthPin and Signed.
func TestGkmProtoImportsOnlyBridge(t *testing.T) {
	imports := testFile(t, testGkmProtoPath).Imports()
	for i := range imports.Len() {
		if path := imports.Get(i).Path(); !strings.HasPrefix(path, "protocol/bridge/") {
			t.Errorf("%s imports %s", testGkmProtoPath, path)
		}
	}
}

// §22.6: seeds in testdata/fuzz/ run in every test.sh. Each message of gkm.proto has FuzzBody's own seeds on disk, as
// one file per encoding that differs from the canonical one, so `go test` runs them as corpus files. Run with
// -update-fuzz-seeds to write a new message's.
func TestGkmBodiesHaveFuzzSeeds(t *testing.T) {
	messages := testFile(t, testGkmProtoPath).Messages()
	for i := range messages.Len() {
		name := string(messages.Get(i).Name())
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(messages.Get(i).FullName())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		canonical := testEncode(t, testFilled(messageType))
		variants := map[string][]byte{
			"canonical":   canonical,
			"reordered":   testReordered(t, canonical),
			"non-minimal": testNonMinimal(t, canonical),
			"unpacked":    testUnpacked(t, messageType.Descriptor(), canonical),
			"repeated":    append(slices.Clone(canonical), canonical...),
			"unknown":     append(slices.Clone(canonical), testUnknownField()...),
		}
		for _, variant := range slices.Sorted(maps.Keys(variants)) {
			encoded := variants[variant]
			if variant != "canonical" && string(encoded) == string(canonical) {
				continue
			}
			path := filepath.Join(testFuzzSeedDirectory, name+"-"+variant)
			if *testUpdateFuzzSeeds {
				seed := fmt.Appendf(nil, "go test fuzz v1\nstring(%q)\n[]byte(%q)\n", name, encoded)
				if err := os.WriteFile(path, seed, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if _, err := os.Stat(path); err != nil {
				t.Errorf("%s has no %s seed: %v", name, variant, err)
			}
		}
	}
}

// FuzzBody returns on a body that does not decode, so a corrupted seed would pass there and test nothing. Each seed
// decodes as the message its file names, and a canonical one re-encodes to itself.
func TestFuzzSeedsDecode(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(testFuzzSeedDirectory, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no seeds found")
	}
	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(source), "\n")
		if len(lines) != 4 || lines[0] != "go test fuzz v1" {
			t.Fatalf("%s does not read as a corpus file", path)
		}
		name, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(lines[1], "string("), ")"))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		encoded, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(lines[2], "[]byte("), ")"))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(testProtoPackage + "." + name))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		message := messageType.New().Interface()
		if err := proto.Unmarshal([]byte(encoded), message); err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if strings.HasSuffix(path, "-canonical") && string(testEncode(t, message)) != encoded {
			t.Errorf("%s is not canonical", path)
		}
	}
}
