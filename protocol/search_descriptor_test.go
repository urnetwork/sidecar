// §11.14's two proto blocks. design_fence_test.go holds every fence to DESIGN.md's text, which moves with the design
// until format 2 freezes; this holds evsindex.proto and search.proto to numbers written here, so a change to both at
// once still fails. It also keeps §22.6's every-body seeds for these messages in testdata/fuzz/FuzzBody, beside the
// target that reads them, so each runs in every go test. Go reads a target's corpus from its own package, which is
// why they sit under protocol/ and not at the module's root.

package protocol

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// Set to rewrite the seed files instead of checking them, as after a field is added before the freeze.
const testWriteSeedsEnvironment = "SIDECAR_WRITE_SEEDS"

const testBodySeedDirectory = "testdata/fuzz/FuzzBody"

var testIndexAndSearchFiles = []string{"protocol/evsindex.proto", "protocol/search.proto"}

// Each message's fields in declaration order, as §11.14 prints them.
var testIndexAndSearchFields = map[protoreflect.Name][]string{
	"IndexSettings":   {"1 off bool", "2 window_days uint32"},
	"IndexLock":       {"1 holder_sidecar_id bytes", "2 bucket_start_day uint32", "3 until_ms int64"},
	"IndexErasureSet": {"1 listed_since uint64", "2 erasures repeated IndexErasure"},
	"IndexErasure": {
		"1 erasure_id bytes", "2 eraser_sidecar_id bytes", "3 epoch uint64", "4 cut_ms int64",
		"5 docs repeated IndexErased",
	},
	"IndexErased": {"1 doc_key bytes", "2 version uint64"},
	"IndexFileHeader": {
		"1 format uint32", "2 type uint32", "3 normalizer uint32", "4 extractor uint32", "5 unicode_version string",
		"6 bucket_start_day uint32", "7 bucket_days uint32", "8 writer_sidecar_id bytes", "9 seq uint32",
		"10 coverage repeated IndexCoverage", "11 pad_generation uint64", "12 body_length uint32", "13 count uint32",
		"14 text_module_version string", "15 tombstones uint32",
	},
	"IndexCoverage": {"1 ref_id bytes", "2 version uint64", "3 horizon bool"},
	"IndexManifest": {
		"1 start_day uint32", "2 days uint32", "3 shards repeated IndexShard", "4 absorbed repeated IndexWatermark",
		"5 rolled_through_day uint32",
	},
	"IndexShard":     {"1 n uint32", "2 docs uint32", "3 first_day uint32", "4 last_day uint32"},
	"IndexWatermark": {"1 writer_sidecar_id bytes", "2 seq uint32"},
	"SearchRequest": {
		"1 search_version uint32", "2 search_id fixed64", "3 page uint32", "4 supersedes fixed64", "5 steps uint32",
		"6 scope uint32", "7 query string", "8 repos repeated SearchRepo", "9 since_ms int64", "10 until_ms int64",
		"11 filters SearchFilters", "12 fuzzy bool", "15 pad bytes",
	},
	"SearchRepo": {"1 repo_id bytes", "2 ref_id bytes"},
	"SearchFilters": {
		"1 agents repeated string", "2 sidecar_ids repeated bytes", "3 member_ids repeated bytes",
		"4 run_ids repeated bytes", "5 session_ids repeated string", "6 kinds repeated uint32", "7 path_prefix string",
		"8 fields repeated SearchField",
	},
	"SearchField": {"1 field uint32", "2 text string"},
	"SearchReply": {
		"1 search_version uint32", "2 min_version uint32", "3 max_version uint32", "4 search_id fixed64",
		"5 page uint32", "6 status uint32", "7 phase uint32", "8 complete bool", "9 checked_through_ms int64",
		"10 coverage repeated SearchCoverage", "11 hits repeated SearchHit", "12 counts SearchCounts", "15 pad bytes",
	},
	"SearchCoverage": {
		"1 repo_id bytes", "2 ref_id bytes", "3 served uint32", "4 ref_version uint64", "5 chain bytes",
		"6 ref_time_ms int64", "7 latest_from_ms int64", "8 uncovered uint32",
	},
	"SearchHit": {
		"1 repo_id bytes", "2 ref_id bytes", "3 doc_key bytes", "4 version uint64", "5 time_ms int64",
		"6 doc_kind uint32", "7 locator string", "8 state uint32", "9 correction string", "10 partition uint32",
		"11 trust uint32", "12 signer bytes", "13 fields repeated SearchField", "14 snippet string", "15 line uint32",
	},
	"SearchCounts": {
		"1 checked uint32", "2 verified uint32", "3 possible uint32", "4 near uint32", "5 masked uint32",
	},
}

// Every top-level message and enum of the two files, in file order.
func testIndexAndSearchDeclarations(t testing.TB) ([]protoreflect.MessageDescriptor, []protoreflect.EnumDescriptor) {
	messages := []protoreflect.MessageDescriptor{}
	enums := []protoreflect.EnumDescriptor{}
	for _, path := range testIndexAndSearchFiles {
		file, err := protoregistry.GlobalFiles.FindFileByPath(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for i := range file.Messages().Len() {
			messages = append(messages, file.Messages().Get(i))
		}
		for i := range file.Enums().Len() {
			enums = append(enums, file.Enums().Get(i))
		}
	}
	return messages, enums
}

// A field as testIndexAndSearchFields writes it.
func testFieldLine(field protoreflect.FieldDescriptor) string {
	line := fmt.Sprintf("%d %s ", field.Number(), field.Name())
	if field.IsList() {
		line += "repeated "
	}
	if field.Message() != nil {
		return line + string(field.Message().Name())
	}
	return line + field.Kind().String()
}

func TestIndexAndSearchFieldNumbersAreAsPrinted(t *testing.T) {
	messages, _ := testIndexAndSearchDeclarations(t)
	if len(messages) != len(testIndexAndSearchFields) {
		t.Errorf("%d messages, and %d listed", len(messages), len(testIndexAndSearchFields))
	}
	for _, message := range messages {
		want, ok := testIndexAndSearchFields[message.Name()]
		if !ok {
			t.Errorf("%s is not listed", message.Name())
			continue
		}
		got := []string{}
		for i := range message.Fields().Len() {
			got = append(got, testFieldLine(message.Fields().Get(i)))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", message.Name(), got, want)
		}
	}
}

// §6.11's rule: a oneof would leave a new case unreadable to an old peer as anything but an unknown field.
func TestIndexAndSearchHoldNoOneof(t *testing.T) {
	messages, _ := testIndexAndSearchDeclarations(t)
	for _, message := range messages {
		if message.Oneofs().Len() != 0 {
			t.Errorf("%s has a oneof", message.Name())
		}
		if message.Messages().Len() != 0 || message.Enums().Len() != 0 {
			t.Errorf("%s nests a declaration, which the design's blocks do not", message.Name())
		}
	}
}

// Fields 13 and 14 stay reserved for later requesters, and nothing else in these files is held back.
func TestOnlySearchRequestReservesNumbers(t *testing.T) {
	messages, _ := testIndexAndSearchDeclarations(t)
	for _, message := range messages {
		want := []int32{}
		if message.Name() == "SearchRequest" {
			want = []int32{13, 14}
		}
		if got := testReservedNumbers(message.ReservedRanges()); !slices.Equal(got, want) {
			t.Errorf("%s reserves %v, want %v", message.Name(), got, want)
		}
		if message.ReservedNames().Len() != 0 {
			t.Errorf("%s reserves a name", message.Name())
		}
	}
}

// A zero is a field no peer set, so it never reads as a status or a served repo: "never reads an unknown status or
// served code as OK or served" (§22.6) starts here.
func TestIndexAndSearchEnumsOpenUnspecified(t *testing.T) {
	_, enums := testIndexAndSearchDeclarations(t)
	if len(enums) != 2 {
		t.Errorf("%d enums", len(enums))
	}
	for _, enum := range enums {
		zero := enum.Values().ByNumber(0)
		if zero == nil || !strings.HasSuffix(string(zero.Name()), "_UNSPECIFIED") {
			t.Errorf("%s's zero is %v", enum.Name(), zero)
		}
	}
}

// D-PROTO-21's numbers, adding none: 0x1402 and 0x1403 stay withdrawn (TestWithdrawnEvsHeadCheckStaysReserved).
func TestRemoteSearchKeepsItsMessageTypes(t *testing.T) {
	if MessageType_SEARCH != 0x1404 || MessageType_SEARCH_RESULT != 0x1405 {
		t.Errorf("SEARCH is %#x and SEARCH_RESULT %#x", int32(MessageType_SEARCH), int32(MessageType_SEARCH_RESULT))
	}
}

// §11.14's determinism row reads a file as a function of its inputs, so a header or manifest must have one encoding:
// fields ascending by number, written the same every time. Nothing here is a map, which is what would break that.
func TestIndexMessagesEncodeInFieldOrder(t *testing.T) {
	for _, name := range []string{"IndexSettings", "IndexLock", "IndexErasureSet", "IndexFileHeader", "IndexManifest"} {
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(testProtoPackage + "." + name))
		if err != nil {
			t.Fatal(err)
		}
		message := testFilled(messageType)
		encoded := testEncode(t, message)
		if !bytes.Equal(testEncode(t, message), encoded) {
			t.Errorf("%s encoded two ways", name)
		}
		last := protowire.Number(0)
		for _, record := range testSplitFields(t, encoded) {
			number, _, _ := protowire.ConsumeTag(record)
			if number < last {
				t.Errorf("%s writes field %d after %d", name, number, last)
			}
			last = number
		}
		fields := messageType.Descriptor().Fields()
		for i := range fields.Len() {
			if fields.Get(i).IsMap() {
				t.Errorf("%s holds a map", name)
			}
		}
	}
}

// One message's seeds by form: §22.6's reordered, repeated, unknown, packed and unpacked fields and non-minimal
// varints. A form that would equal the canonical bytes is left out.
func testBodySeeds(t testing.TB, message protoreflect.MessageDescriptor, encoded []byte) map[string][]byte {
	seeds := map[string][]byte{
		"canonical": encoded,
		"repeated":  append(slices.Clone(encoded), encoded...),
		"unknown":   append(slices.Clone(encoded), testUnknownField()...),
	}
	for form, variant := range map[string][]byte{
		"reordered":   testReordered(t, encoded),
		"non-minimal": testNonMinimal(t, encoded),
		"unpacked":    testUnpacked(t, message, encoded),
	} {
		if !bytes.Equal(variant, encoded) {
			seeds[form] = variant
		}
	}
	return seeds
}

// A corpus file of FuzzBody's two arguments, in the form go test reads.
func testCorpusFile(name string, body []byte) []byte {
	return fmt.Appendf(nil, "go test fuzz v1\nstring(%q)\n[]byte(%q)\n", name, body)
}

func TestEveryIndexAndSearchBodyHasItsSeeds(t *testing.T) {
	messages, _ := testIndexAndSearchDeclarations(t)
	write := os.Getenv(testWriteSeedsEnvironment) != ""
	forms := map[string]int{}
	for _, message := range messages {
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(message.FullName())
		if err != nil {
			t.Fatal(err)
		}
		for form, body := range testBodySeeds(t, message, testEncode(t, testFilled(messageType))) {
			forms[form]++
			path := filepath.Join(testBodySeedDirectory, string(message.Name())+"-"+form)
			corpus := testCorpusFile(string(message.Name()), body)
			if write {
				if err := os.MkdirAll(testBodySeedDirectory, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, corpus, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			held, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("%s: %v; %s=1 writes it", path, err, testWriteSeedsEnvironment)
				continue
			}
			if !bytes.Equal(held, corpus) {
				t.Errorf("%s is stale; %s=1 rewrites it", path, testWriteSeedsEnvironment)
			}
		}
	}
	// A form no message reached is a form the corpus does not hold.
	for _, form := range []string{"canonical", "repeated", "unknown", "reordered", "non-minimal", "unpacked"} {
		if forms[form] == 0 {
			t.Errorf("no seed of form %s", form)
		}
	}
}

// §22.6's round trip on the seeds themselves: however a seed was encoded it decodes, and every form but the doubled
// one is the same message.
func TestIndexAndSearchSeedsDecodeAlike(t *testing.T) {
	messages, _ := testIndexAndSearchDeclarations(t)
	for _, message := range messages {
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(message.FullName())
		if err != nil {
			t.Fatal(err)
		}
		filled := testFilled(messageType)
		for form, body := range testBodySeeds(t, message, testEncode(t, filled)) {
			decoded := messageType.New().Interface()
			if err := proto.Unmarshal(body, decoded); err != nil {
				t.Errorf("%s %s: %v", message.Name(), form, err)
				continue
			}
			switch form {
			case "repeated":
			case "unknown":
				decoded.ProtoReflect().SetUnknown(nil)
				fallthrough
			default:
				if !proto.Equal(filled, decoded) {
					t.Errorf("%s %s decoded differently", message.Name(), form)
				}
			}
		}
	}
}
