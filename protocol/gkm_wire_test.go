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

// 10.6's checks and 10.8: a re-form writes its new group's epoch 0 with its form, as KF1 writes a creation's, so each
// field of epoch 0 a client supplies rides both routes' requests, of the same kind. Only a creation carries a
// GenRotate: a re-form's generations come by the ladder, the old group's bytes, which a gen/1 written here would clash
// with.
func TestGkmReformCarriesEpochZero(t *testing.T) {
	message := func(name string) protoreflect.MessageDescriptor {
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(testProtoPackage + "." + name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return messageType.Descriptor()
	}
	// what gkm writes into an epoch object itself, from the token, its clock, the commit and the form
	gkmWrittenNames := []protoreflect.Name{"commit", "header", "uploader", "time_ms", "group_info_generation", "network_id"}
	epochFields := message("GkmEpochObject").Fields()
	for _, gkmWrittenName := range gkmWrittenNames {
		if epochFields.ByName(gkmWrittenName) == nil {
			t.Fatalf("GkmEpochObject has no %s", gkmWrittenName)
		}
	}
	for _, requestName := range []string{"GkmGroupCreateRequest", "GkmGroupReformRequest"} {
		requestFields := message(requestName).Fields()
		if form := requestFields.ByName("form"); form == nil || form.Message() == nil || form.Message().Name() != "Signed" {
			t.Errorf("%s carries no Signed form", requestName)
		}
		for i := range epochFields.Len() {
			epochField := epochFields.Get(i)
			if slices.Contains(gkmWrittenNames, epochField.Name()) {
				continue
			}
			requestField := requestFields.ByName(epochField.Name())
			if requestField == nil {
				t.Errorf("%s does not carry epoch 0's %s", requestName, epochField.Name())
			} else if requestField.Kind() != epochField.Kind() || requestField.Cardinality() != epochField.Cardinality() {
				t.Errorf("%s.%s is not of epoch 0's kind", requestName, epochField.Name())
			}
		}
	}
	if message("GkmGroupReformRequest").Fields().ByName("gen_rotate") != nil {
		t.Error("GkmGroupReformRequest carries a GenRotate, which the ladder's gen/1 would clash with")
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
