// gkm.proto against what §4.7 and §22.6 ask of it: no service block, nothing past protocol/bridge, and §22.6's seeds on
// disk for every message. sidecartest's gkm_fields_test.go holds each field to its §2.8 row.

package protocol

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
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
	testFuzzSeedDirectory = "testdata/fuzz/FuzzBody"
)

// Writes the seeds, for a message that has none yet.
var testUpdateFuzzSeeds = flag.Bool(
	"update-fuzz-seeds", false, "write gkm.proto's seeds under testdata/fuzz/FuzzBody instead of checking for them",
)

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
