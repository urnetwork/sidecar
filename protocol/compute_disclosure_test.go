// compute_disclosure.proto held to the numbers written here (CTRUST-M12-02): design_fence_test.go holds its declaration
// to testUnfencedFence, which moves with the design until the format freezes, so this keeps the fields as written, and a
// change to both at once still fails. The statement's signing and judging are the root's (disclosure_network.go), whose
// tests hold its signed bytes and refusals.

package protocol

import (
	"bytes"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

const testComputeDisclosureProtoPath = "protocol/compute_disclosure.proto"

// DisclosureAck's fields in declaration order: §2.8's list in the order it writes it, then the signing device and its
// pin.
var testDisclosureAckFields = []string{
	"1 network_id bytes", "2 disclosure_id string", "3 version uint32", "4 locale string", "5 revision uint32",
	"6 member_id bytes", "7 sidecar_id bytes", "8 auth_pin AuthPin",
}

// The file declares DisclosureAck alone, each field at its number and kind, with no oneof, nested declaration,
// reservation or explicit presence.
func TestDisclosureAckDescriptor(t *testing.T) {
	file := testFile(t, testComputeDisclosureProtoPath)
	if file.Messages().Len() != 1 || file.Enums().Len() != 0 || file.Services().Len() != 0 {
		t.Fatalf("%s declares %d messages and %d enums, want DisclosureAck alone", testComputeDisclosureProtoPath,
			file.Messages().Len(), file.Enums().Len())
	}
	message := file.Messages().ByName("DisclosureAck")
	if message == nil {
		t.Fatal("no DisclosureAck")
	}
	got := []string{}
	for i := range message.Fields().Len() {
		field := message.Fields().Get(i)
		got = append(got, testListenersFieldLine(field))
		if field.HasPresence() && field.Message() == nil {
			t.Errorf("DisclosureAck.%s has explicit presence", field.Name())
		}
	}
	if !slices.Equal(got, testDisclosureAckFields) {
		t.Errorf("DisclosureAck:\n got %q\nwant %q", got, testDisclosureAckFields)
	}
	if message.Oneofs().Len() != 0 || message.Messages().Len() != 0 || message.Enums().Len() != 0 ||
		message.ReservedRanges().Len() != 0 || message.ReservedNames().Len() != 0 {
		t.Error("DisclosureAck holds a oneof, nests a declaration or reserves numbers")
	}
	if pin := message.Fields().ByName("auth_pin").Message(); pin.FullName() != protoreflect.FullName(testProtoPackage+".AuthPin") {
		t.Errorf("auth_pin is a %s", pin.FullName())
	}
}

// A statement encodes deterministically and reads back whole: the bytes a signature covers do not depend on how the
// fields were set.
func TestDisclosureAckRoundTrip(t *testing.T) {
	statement := &DisclosureAck{
		NetworkId:    bytes.Repeat([]byte{0x01}, 16),
		DisclosureId: "inference:engy",
		Version:      2,
		Locale:       "de",
		Revision:     3,
		MemberId:     bytes.Repeat([]byte{0x02}, 16),
		SidecarId:    bytes.Repeat([]byte{0x03}, 16),
		AuthPin:      &bridge.AuthPin{Version: 41, Chain: bytes.Repeat([]byte{0x04}, 32)},
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	again, err := proto.MarshalOptions{Deterministic: true}.Marshal(proto.Clone(statement))
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatalf("two encodings differ: %v", err)
	}
	decoded := &DisclosureAck{}
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(decoded, statement) || len(decoded.ProtoReflect().GetUnknown()) != 0 {
		t.Errorf("read back %v", decoded)
	}
}
