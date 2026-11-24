// attest.proto held to numbers written here (ATTEST-M11-01, ATTEST-M12-01): design_fence_test.go holds
// AttestationResult to DESIGN-COMPUTE.md §5.8's fence and the tickets to testUnfencedFence, each of which moves with
// the design until the format freezes, so this keeps the fields as written, and a change to both at once still fails.

package protocol

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const testAttestProtoPath = "protocol/attest.proto"

// Each message's fields in declaration order, as §5.8 prints AttestationResult's.
var testAttestFields = map[protoreflect.Name][]string{
	"AttestationResult": {
		"1 provider string", "2 label string", "3 scheme string", "4 cpu string", "5 profile_id string",
		"6 profile_review string", "7 tcb string", "8 gpus repeated string", "9 policy_version uint64",
		"10 evidence_sha256 bytes", "11 key_sha256 bytes", "12 instance_id string", "13 verified_millis int64",
		"14 verifier string", "15 provider_model_id string",
	},
	// §5.4's freshness tickets, numbered in the order §5.4 writes their fields (QD-1379; ATTEST-M12-01)
	"ComputePolicyTicketBatch": {"1 batch_id bytes", "2 signed_at_ms int64", "3 expires_ms int64"},
	"ComputePolicyTicket": {
		"1 format uint32", "2 batch ComputePolicyTicketBatch", "3 policy_version uint64", "4 not_before_ms int64",
		"5 not_after_ms int64",
	},
	"ComputePolicyTicketFile": {"1 ticket bytes", "2 signature bytes"},
}

// §5.8's fields 1 to 15 and the tickets', each at its number, in its order, with nothing else in the file.
func TestAttestationResultDescriptor(t *testing.T) {
	file := testFile(t, testAttestProtoPath)
	messages := file.Messages()
	if messages.Len() != len(testAttestFields) {
		t.Errorf("%s declares %d messages, and %d are listed", testAttestProtoPath, messages.Len(), len(testAttestFields))
	}
	for i := range messages.Len() {
		message := messages.Get(i)
		want, ok := testAttestFields[message.Name()]
		if !ok {
			t.Errorf("%s is not listed", message.Name())
			continue
		}
		got := []string{}
		for j := range message.Fields().Len() {
			got = append(got, testFieldLine(message.Fields().Get(j)))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", message.Name(), got, want)
		}
		if message.Oneofs().Len() != 0 || message.Messages().Len() != 0 || message.Enums().Len() != 0 {
			t.Errorf("%s holds a oneof or nests a declaration", message.Name())
		}
		if message.ReservedRanges().Len() != 0 || message.ReservedNames().Len() != 0 {
			t.Errorf("%s reserves what §5.8 does not", message.Name())
		}
	}
	if file.Enums().Len() != 0 {
		t.Errorf("%s declares an enum §5.8 does not", testAttestProtoPath)
	}
}

// A result round-trips: what a device records is what a reader of the record decodes, field for field.
func TestAttestationResultRoundTrips(t *testing.T) {
	result := &AttestationResult{
		Provider:        "chutes",
		Label:           "AP",
		Scheme:          "chutes-e2e-v1",
		Cpu:             "tdx",
		ProfileId:       "profile-test-1",
		ProfileReview:   "reproduced",
		Tcb:             "UpToDate",
		Gpus:            []string{"b200", "b200"},
		PolicyVersion:   7,
		EvidenceSha256:  make([]byte, 32),
		KeySha256:       make([]byte, 32),
		InstanceId:      "instance-test-1",
		VerifiedMillis:  1767323045000,
		Verifier:        "ur test / nras",
		ProviderModelId: "chute-test-1",
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &AttestationResult{}
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(result, decoded) {
		t.Errorf("decoded %v, want %v", decoded, result)
	}
}
