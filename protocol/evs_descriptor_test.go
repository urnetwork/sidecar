// evs.proto's own lints beside FS-72's, which evs_reserved_test.go reads from testdata/evs/reserved_numbers.yml: the
// flag words' bits, EvsEntryVersion's missing field 15, the numbers of what EVS-FORMAT.md proposes where neither a
// design fence nor testdata/evs/metadata_rows.yml pins them, and §22.6's every-body seeds for each evs message in
// testdata/fuzz/FuzzBody, beside the target that reads them, so each runs in every go test.

package protocol

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// §11.8's entry row: bits 16-31 hold the change count, so no flag may reach them, and each is one bit.
func TestWindowFlagsStayBelowTheChangeCount(t *testing.T) {
	for number, name := range EvsWindowFlag_name {
		if number == 0 {
			continue
		}
		if number&(number-1) != 0 || number >= 1<<16 {
			t.Errorf("%s is %#x", name, number)
		}
	}
}

// EvsPush.flags is a bit set: a value of two bits would read as two flags.
func TestPushFlagsAreOneBitEach(t *testing.T) {
	for number, name := range EvsPushFlag_name {
		if number != 0 && number&(number-1) != 0 {
			t.Errorf("%s is %#x", name, number)
		}
	}
}

// Owner decisions 165 and 167: versionless means head-only, so field 15 is neither used nor held back.
func TestEntryVersionHasNoFieldFifteen(t *testing.T) {
	message := testMessage(t, "EvsEntryVersion")
	if message.Fields().ByNumber(15) != nil {
		t.Error("field 15 is in use")
	}
	if message.ReservedRanges().Has(15) {
		t.Error("field 15 is reserved")
	}
}

// EVS-FORMAT.md's enumerations, each value as written there. plan-EVS1-format-bytes#3 and #6 to #8 give most; the
// refusal codes from 64 and the outcome are EVS-FORMAT.md's own, and its table gives every code's status.
func TestEvsEnumNumbersStable(t *testing.T) {
	cases := []struct {
		name string
		got  map[string]int32
		want map[string]int32
	}{
		{
			name: "EvsRefKind",
			got:  EvsRefKind_value,
			want: map[string]int32{
				"EVS_REF_KIND_UNSPECIFIED": 0, "EVS_REF_SHARED": 1, "EVS_REF_OWNED": 2, "EVS_REF_DEPOSIT": 3,
				"EVS_REF_ERASURE": 4,
			},
		},
		{
			name: "EvsRefMode",
			got:  EvsRefMode_value,
			want: map[string]int32{"EVS_REF_MODE_UNSPECIFIED": 0, "EVS_REF_GIT": 1, "EVS_REF_FILE": 2},
		},
		{
			name: "EvsEntryKind",
			got:  EvsEntryKind_value,
			want: map[string]int32{"EVS_ENTRY_KIND_UNSPECIFIED": 0, "EVS_ENTRY_FILE": 1, "EVS_ENTRY_DIRECTORY": 2},
		},
		{
			name: "EvsRecordKind",
			got:  EvsRecordKind_value,
			want: map[string]int32{
				"EVS_RECORD_KIND_UNSPECIFIED": 0, "EVS_RECORD_CHECKPOINT": 1, "EVS_RECORD_DIFF": 2, "EVS_RECORD_CHUNK": 3,
			},
		},
		{
			name: "EvsKeyRefKind",
			got:  EvsKeyRefKind_value,
			want: map[string]int32{"EVS_KEY_REF_CONTAINER": 0, "EVS_KEY_REF_SLOT": 1},
		},
		{
			name: "EvsOidKind",
			got:  EvsOidKind_value,
			want: map[string]int32{"EVS_OID_KIND_UNSPECIFIED": 0, "EVS_OID_SHA1": 1, "EVS_OID_SHA256": 2},
		},
		{
			name: "EvsBatchRecordType",
			got:  EvsBatchRecordType_value,
			want: map[string]int32{
				"EVS_BATCH_RECORD_TYPE_UNSPECIFIED": 0, "EVS_BATCH_PUSH": 1, "EVS_BATCH_PART": 2, "EVS_BATCH_SEAL": 3,
				"EVS_BATCH_RESEED": 4,
			},
		},
		{
			name: "EvsPayloadSection",
			got:  EvsPayloadSection_value,
			want: map[string]int32{
				"EVS_PAYLOAD_SECTION_UNSPECIFIED": 0, "EVS_PAYLOAD_ENTRY_VERSIONS": 1, "EVS_PAYLOAD_SEALED_METADATA": 2,
				"EVS_PAYLOAD_INLINE_RECORDS": 3, "EVS_PAYLOAD_CHANGE_LIST": 4, "EVS_PAYLOAD_PART_HASHES": 5,
				"EVS_PAYLOAD_NEW_OBJECTS": 6, "EVS_PAYLOAD_SLOT_BODIES": 7, "EVS_PAYLOAD_ERASED_LIST": 8,
				"EVS_PAYLOAD_DROP_BODY": 9, "EVS_PAYLOAD_DROP_LISTS": 10, "EVS_PAYLOAD_TAIL_MOVES": 11,
				"EVS_PAYLOAD_SOURCE_PATHS": 12, "EVS_PAYLOAD_REUSE_LIST": 13, "EVS_PAYLOAD_MERKLE_PROOFS": 14,
				"EVS_PAYLOAD_REF_NAME": 15, "EVS_PAYLOAD_OVERLAY_BASE": 16,
			},
		},
		{
			name: "EvsGitShape",
			got:  EvsGitShape_value,
			want: map[string]int32{
				"EVS_GIT_SHAPE_UNSPECIFIED": 0, "EVS_GIT_UPDATE": 1, "EVS_GIT_DELETE": 2, "EVS_GIT_REKEY": 3,
			},
		},
		{
			name: "EvsNewObjectKind",
			got:  EvsNewObjectKind_value,
			want: map[string]int32{
				"EVS_NEW_OBJECT_KIND_UNSPECIFIED": 0, "EVS_NEW_OBJECT_SEGMENT": 1, "EVS_NEW_OBJECT_STAGED_SEGMENT": 2,
				"EVS_NEW_OBJECT_SLOT": 3,
			},
		},
		{
			name: "EvsRepoState",
			got:  EvsRepoState_value,
			want: map[string]int32{
				"EVS_REPO_STATE_UNSPECIFIED": 0, "EVS_REPO_KEYING": 1, "EVS_REPO_ACTIVE": 2, "EVS_REPO_DELETED": 3,
				"EVS_REPO_SHREDDING": 4, "EVS_REPO_SHREDDED": 5,
			},
		},
		{
			name: "EvsRefusalCode",
			got:  EvsRefusalCode_value,
			want: map[string]int32{
				"EVS_REFUSAL_CODE_UNSPECIFIED": 0, "EVS_REFUSAL_SCOPE": 1, "EVS_REFUSAL_TIME_STALE": 2,
				"EVS_REFUSAL_REPO_KEYING": 3, "EVS_REFUSAL_REPO_DELETED": 4, "EVS_REFUSAL_QUOTA_PAYMENT": 5,
				"EVS_REFUSAL_QUOTA_LIMIT": 6, "EVS_REFUSAL_CLUSTER_FULL": 7, "EVS_REFUSAL_GATE_CLOSED": 8,
				"EVS_REFUSAL_INDEX_EPOCH": 9, "EVS_REFUSAL_MAP_PARTS": 10, "EVS_REFUSAL_EPOCH_SOURCES_FULL": 11,
				"EVS_REFUSAL_PATH_EPOCH_DUE": 12, "EVS_REFUSAL_DIRECTORY_FULL": 13, "EVS_REFUSAL_SEGMENT_GONE": 14,
				"EVS_REFUSAL_VERSIONING": 15, "EVS_REFUSAL_SLOT_UNKNOWN": 16, "EVS_REFUSAL_SLOT_STALE": 17,
				"EVS_REFUSAL_NOTHING_TO_ERASE": 18, "EVS_REFUSAL_DROPPED": 19, "EVS_REFUSAL_DROP_PATH": 20,
				"EVS_REFUSAL_DROP_CONSENT": 21, "EVS_REFUSAL_DROP_STATE": 22, "EVS_REFUSAL_DROP_BOUNDARY": 23,
				"EVS_REFUSAL_DROP_LIST": 24, "EVS_REFUSAL_FORMAT_UNSUPPORTED": 25,
				"EVS_REFUSAL_REF_MODE": 64, "EVS_REFUSAL_PUSH_ID_REUSED": 65, "EVS_REFUSAL_NON_FAST_FORWARD": 66,
				"EVS_REFUSAL_BASE_STALE": 67, "EVS_REFUSAL_PATH_CONFLICT": 68, "EVS_REFUSAL_PATH_EPOCH": 69,
				"EVS_REFUSAL_SHREDDING": 70, "EVS_REFUSAL_DROP_KIND": 71, "EVS_REFUSAL_SEGMENT_STALE": 72,
				"EVS_REFUSAL_STATEMENT_MISSING": 73, "EVS_REFUSAL_GROUP_NOT_READY": 74, "EVS_REFUSAL_MAP_SOURCE": 75,
				"EVS_REFUSAL_INVALID": 128, "EVS_REFUSAL_NOT_FOUND": 129, "EVS_REFUSAL_PARTS_MISSING": 130,
				"EVS_REFUSAL_BUSY": 131, "EVS_REFUSAL_FOLD_BEHIND": 132, "EVS_REFUSAL_TIME_AHEAD": 133,
				"EVS_REFUSAL_RESOURCE_EXHAUSTED": 134, "EVS_REFUSAL_WAIT": 135, "EVS_REFUSAL_UNAVAILABLE": 136,
			},
		},
		{
			name: "EvsPushOutcome",
			got:  EvsPushOutcome_value,
			want: map[string]int32{"EVS_PUSH_OUTCOME_SETTLED": 0, "EVS_PUSH_OUTCOME_UNKNOWN": 1},
		},
		{
			name: "EvsReadPathState",
			got:  EvsReadPathState_value,
			want: map[string]int32{
				"EVS_READ_PATH_STATE_UNSPECIFIED": 0, "EVS_READ_PATH_COLLECTED": 1, "EVS_READ_PATH_DROP_PENDING": 2,
				"EVS_READ_PATH_DROPPED": 3,
			},
		},
		{
			name: "EvsReadObjectKind",
			got:  EvsReadObjectKind_value,
			want: map[string]int32{
				"EVS_READ_OBJECT_KIND_UNSPECIFIED": 0, "EVS_READ_OBJECT_SEGMENT": 1, "EVS_READ_OBJECT_SLOT": 2,
				"EVS_READ_OBJECT_MAP_PART": 3, "EVS_READ_OBJECT_LOG_PAGE": 4, "EVS_READ_OBJECT_BATCH_RECORD": 5, "EVS_READ_OBJECT_RESEED": 6,
			},
		},
	}
	for _, c := range cases {
		if !maps.Equal(c.got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

// The refusal table's ranges hold: the head's 16 B EvsRefusal keeps a code in 2 bytes, and the ranges tell a
// recordable code from a final one and from an answer that refuses nothing by number alone.
func TestEvsRefusalCodesKeepTheirRanges(t *testing.T) {
	recordable := 0
	for number, name := range EvsRefusalCode_name {
		switch {
		case number < 0 || 1<<16 <= number:
			t.Errorf("%s is %d, past the record's 2 bytes", name, number)
		case 25 < number && number < 64, 75 < number && number < 128, 136 < number:
			t.Errorf("%s is %d, outside the ranges EVS-FORMAT.md gives", name, number)
		case 0 < number && number < 64:
			recordable++
		}
	}
	if recordable != 25 {
		t.Errorf("%d recordable codes, and plan-EVS1-format-bytes#6 numbers 25", recordable)
	}
}

// The sealed values EVS-FORMAT.md proposes, which no server reads, so testdata/evs/metadata_rows.yml does not pin
// them: each field as testFieldLine writes it, in declaration order.
func TestEvsSealedValuesKeepTheirNumbers(t *testing.T) {
	want := map[protoreflect.Name][]string{
		"EvsSealedFields": {
			"1 file_id bytes", "2 mode uint32", "3 git_oid bytes", "4 oid_kind enum", "5 size uint64",
			"6 content_sha256 bytes",
		},
		"EvsSealedMetadata": {
			"1 group GroupHead", "2 provenance EvsProvenance", "3 commits repeated EvsSealedCommit",
			"4 signed_import bytes", "5 git EvsGitUpdate", "6 ref_name bytes", "7 base EvsOverlay",
			"8 erasure_note bytes",
		},
		"EvsProvenance": {"1 agent_id bytes", "2 tainted bool"},
		"EvsSealedCommit": {
			"1 object bytes", "2 changes repeated EvsSealedChange", "3 trees repeated EvsSealedTree",
		},
		"EvsSealedChange": {"1 path repeated bytes", "2 mode uint32", "3 git_oid bytes"},
		// DESIGN-DETAILS 8.2.2's git update, sealed, so no server reads it
		"EvsGitUpdate": {
			"1 shape enum", "2 old_tip bytes", "3 new_tip bytes", "4 tags repeated bytes",
			"5 sources repeated EvsOverlay", "6 segment_ids repeated bytes", "7 blobs repeated EvsSealedBlob",
		},
		"EvsSealedBlob": {
			"1 git_oid bytes", "2 size uint64", "3 base_oid bytes", "4 file_id bytes",
			"5 records repeated EvsHistoryLocator",
		},
		"EvsHistoryLocator": {"1 segment uint32", "2 offset uint32", "3 length uint32"},
		"EvsSealedTree":     {"1 path repeated bytes", "2 object bytes"},
	}
	for _, name := range slices.Sorted(maps.Keys(want)) {
		message := testMessage(t, string(name))
		got := []string{}
		for i := range message.Fields().Len() {
			got = append(got, testFieldLine(message.Fields().Get(i)))
		}
		if !slices.Equal(got, want[name]) {
			t.Errorf("%s:\n got %q\nwant %q", name, got, want[name])
		}
	}
}

// Every message evs.proto declares, in file order.
func testEvsMessages(t testing.TB) []protoreflect.MessageDescriptor {
	file, err := protoregistry.GlobalFiles.FindFileByPath("protocol/evs.proto")
	if err != nil {
		t.Fatal(err)
	}
	messages := []protoreflect.MessageDescriptor{}
	for i := range file.Messages().Len() {
		messages = append(messages, file.Messages().Get(i))
	}
	if len(messages) < 50 {
		t.Fatalf("found %d evs messages", len(messages))
	}
	return messages
}

// Each evs message's §22.6 seeds are on disk as the encoder writes them today, so a field added or renumbered before
// the freeze shows as a rewritten seed. SIDECAR_WRITE_SEEDS=1 rewrites them.
func TestEveryEvsBodyHasItsSeeds(t *testing.T) {
	write := os.Getenv(testWriteSeedsEnvironment) != ""
	forms := map[string]int{}
	for _, message := range testEvsMessages(t) {
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
	for _, form := range []string{"canonical", "repeated", "unknown", "reordered", "non-minimal", "unpacked"} {
		if forms[form] == 0 {
			t.Errorf("no evs seed of form %s", form)
		}
	}
}

// §22.6's round trip on the evs seeds: however a seed was encoded it decodes, and every form but the doubled one is
// the message it came from, proto.Equal to it.
func TestEvsSeedsDecodeAlike(t *testing.T) {
	for _, message := range testEvsMessages(t) {
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
