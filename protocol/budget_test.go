// Bounds the design states on a message, held at each message's worst case. testFillToWidths fills from the descriptor,
// not by hand, so a field added later takes its place in the worst case: a number goes in at its widest, and a string,
// bytes or list field stops the test until testFieldWidths says how wide the design lets it grow. Identifiers are the
// design's 16 B ids and 32 B hashes, and numbers the widest a varint holds, so these overstate what a real ticket or
// hint takes.

package protocol

import (
	"bytes"
	"fmt"
	"maps"
	"math"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const (
	// A sidecar, network, client, group, ref or listen id, and a ticket's id.
	testIdSize = 16
	// A chain digest or header hash.
	testHashSize = 32
	// An Ed25519 signature (§9.6: a service key fixes the algorithm).
	testSignatureSize = 64

	// §6.8: a hint is at most this, inside PushHint.hint.
	testHintBound = 256
	// §9.6's comment on SocketTicket.
	testTicketBound = 370
	// §9.6's comment on SignedSocketTicket.
	testSignedTicketBound = 512
	// §16.11: q/<tgt>/<rid>, padded to this.
	testNoticeBound = 256
	// §16.11's DirectoryNotice.decisions: at most the rule's 2.
	testNoticeDecisions = 2
)

// How wide the design lets each string and bytes field grow, and how long each list, by message and field. A width of
// 0 leaves the field unset, for a test whose case excludes it.
var testFieldWidths = map[string]int{
	"SocketHint.listen_id": testIdSize,

	"SocketTicket.ticket_id":          testIdSize,
	"SocketTicket.network_id":         testIdSize,
	"SocketTicket.name":               112,
	"SocketTicket.listener_client_id": testIdSize,
	"SocketTicket.listen_id":          testIdSize,
	"SocketTicket.dialer_client_id":   testIdSize,
	"SocketTicket.dialer_network_id":  testIdSize,
	"SocketTicket.grant_id":           testIdSize,
	"SocketTicket.name_token":         8 * testIdSize,

	// §9.6 gives a service key's id no width, so this only stands well past any name a key would take.
	"SignedSocketTicket.key_id":    64,
	"SignedSocketTicket.signature": testSignatureSize,

	"GkmHint.group_id": testIdSize,
	// d: and a delegation_id, the longest recipient 10.6 names, its hex form the longest it could take.
	"GkmHint.recipient": 2 + 2*testHashSize,

	"EvsHeadChanged.ref_id":  testIdSize,
	"EvsHeadChanged.chain":   testHashSize,
	"EvsHeadChanged.push_id": testIdSize,

	"DirectoryNotice.request_id":           testIdSize,
	"DirectoryNotice.requester_sidecar_id": testIdSize,
	"DirectoryNotice.decisions":            testNoticeDecisions,
	"DecisionRef.decider_sidecar_id":       testIdSize,
	"DecisionRef.header_sha256":            testHashSize,
}

// Stands for an identifier or hash of this size.
func testBytes(size int) []byte {
	return bytes.Repeat([]byte{0xFF}, size)
}

// What a message takes on the wire.
func testSize(t *testing.T, message proto.Message) int {
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return len(encoded)
}

// Sets every field of message at its widest, nested messages included, so nothing can sit unset and cost no bytes. A
// string, bytes or list field fieldWidths does not name is an error: nothing else can say how far it grows. So is a
// map, and a list of strings or bytes, which no bounded message holds yet and which would need a width per element.
func testFillToWidths(message protoreflect.Message, fieldWidths map[string]int) error {
	// A negative int32 or int64 takes ten bytes, the most a varint does, and an enum its highest number.
	widestNumber := func(field protoreflect.FieldDescriptor) protoreflect.Value {
		switch field.Kind() {
		case protoreflect.BoolKind:
			return protoreflect.ValueOfBool(true)
		case protoreflect.EnumKind:
			values := field.Enum().Values()
			return protoreflect.ValueOfEnum(values.Get(values.Len() - 1).Number())
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
			return protoreflect.ValueOfInt32(math.MinInt32)
		case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
			return protoreflect.ValueOfUint32(math.MaxUint32)
		case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
			return protoreflect.ValueOfInt64(math.MinInt64)
		case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			return protoreflect.ValueOfUint64(math.MaxUint64)
		case protoreflect.FloatKind:
			return protoreflect.ValueOfFloat32(math.MaxFloat32)
		case protoreflect.DoubleKind:
			return protoreflect.ValueOfFloat64(math.MaxFloat64)
		}
		panic(fmt.Sprintf("%s has kind %s", field.FullName(), field.Kind()))
	}
	descriptor := message.Descriptor()
	fields := descriptor.Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		key := string(descriptor.Name()) + "." + string(field.Name())
		width, stated := fieldWidths[key]
		textual := field.Kind() == protoreflect.StringKind || field.Kind() == protoreflect.BytesKind
		switch {
		case field.IsMap():
			return fmt.Errorf("%s is a map, which this cannot bound", key)
		case field.IsList() && textual:
			return fmt.Errorf("%s is a list of %s, which this cannot bound", key, field.Kind())
		case (field.IsList() || textual) && !stated:
			return fmt.Errorf("%s has no stated width", key)
		case field.IsList():
			list := message.Mutable(field).List()
			for range width {
				if field.Message() == nil {
					list.Append(widestNumber(field))
					continue
				}
				element := list.NewElement()
				if err := testFillToWidths(element.Message(), fieldWidths); err != nil {
					return err
				}
				list.Append(element)
			}
		case field.Message() != nil:
			if err := testFillToWidths(message.Mutable(field).Message(), fieldWidths); err != nil {
				return err
			}
		case field.Kind() == protoreflect.StringKind:
			message.Set(field, protoreflect.ValueOfString(strings.Repeat("n", width)))
		case field.Kind() == protoreflect.BytesKind:
			message.Set(field, protoreflect.ValueOfBytes(testBytes(width)))
		default:
			message.Set(field, widestNumber(field))
		}
	}
	return nil
}

// §9.6: a ticket fits with a 112-byte name or an 8-segment token path, and a signed one in StreamOpen.ticket. A ticket
// carries one or the other, so each case leaves one out.
func TestSocketTicketFitsItsBounds(t *testing.T) {
	for _, unset := range []string{"SocketTicket.name", "SocketTicket.name_token"} {
		fieldWidths := maps.Clone(testFieldWidths)
		fieldWidths[unset] = 0

		ticket := &SocketTicket{}
		if err := testFillToWidths(ticket.ProtoReflect(), fieldWidths); err != nil {
			t.Fatal(err)
		}
		size := testSize(t, ticket)
		if size > testTicketBound {
			t.Errorf("without %s a ticket takes %d B, over %d", unset, size, testTicketBound)
		}

		fieldWidths["SignedSocketTicket.ticket"] = size
		signed := &SignedSocketTicket{}
		if err := testFillToWidths(signed.ProtoReflect(), fieldWidths); err != nil {
			t.Fatal(err)
		}
		if size := testSize(t, signed); size > testSignedTicketBound {
			t.Errorf("without %s a signed ticket takes %d B, over %d", unset, size, testSignedTicketBound)
		}
	}
}

// §6.8: PushHint.hint holds ids, kinds and versions, and is dropped when coalesced.
func TestHintsFitPushHint(t *testing.T) {
	for _, message := range []proto.Message{&SocketHint{}, &GkmHint{}, &EvsHeadChanged{}, &MailHint{}} {
		name := message.ProtoReflect().Descriptor().Name()
		if err := testFillToWidths(message.ProtoReflect(), testFieldWidths); err != nil {
			t.Fatal(err)
		}
		if size := testSize(t, message); size > testHintBound {
			t.Errorf("%s takes %d B, over %d", name, size, testHintBound)
		}
	}
}

// §16.11: a notice names up to the rule's two approvals and still pads to 256 B.
func TestDirectoryNoticeFitsItsBound(t *testing.T) {
	notice := &DirectoryNotice{}
	if err := testFillToWidths(notice.ProtoReflect(), testFieldWidths); err != nil {
		t.Fatal(err)
	}
	if size := testSize(t, notice); size > testNoticeBound {
		t.Errorf("a notice takes %d B, over %d", size, testNoticeBound)
	}
}

// The promise above, on fields planted in a copy: each unbounded field a review added stops the fill, and a number
// takes its full width, so neither can sit unset beneath a bound. The real messages fill with nothing left unset.
func TestBoundsReachAFieldAddedLater(t *testing.T) {
	bytesKind := descriptorpb.FieldDescriptorProto_TYPE_BYTES
	stringKind := descriptorpb.FieldDescriptorProto_TYPE_STRING
	repeated := testNewField("stray_ids", 6, descriptorpb.FieldDescriptorProto_TYPE_UINT64)
	repeated.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	cases := []struct {
		path    string
		message string
		field   *descriptorpb.FieldDescriptorProto
		want    string
	}{
		{
			path:    "protocol/gkm.proto",
			message: "GkmHint",
			field:   testNewField("blob", 5, bytesKind),
			want:    "GkmHint.blob has no stated width",
		},
		{
			path:    "protocol/evs.proto",
			message: "EvsHeadChanged",
			field:   testNewField("sealed_path", 5, bytesKind),
			want:    "EvsHeadChanged.sealed_path has no stated width",
		},
		{
			path:    "protocol/socket.proto",
			message: "SocketTicket",
			field:   testNewField("extra", 16, bytesKind),
			want:    "SocketTicket.extra has no stated width",
		},
		{
			path:    "protocol/socket.proto",
			message: "SocketHint",
			field:   testNewField("note", 3, stringKind),
			want:    "SocketHint.note has no stated width",
		},
		{
			path:    "protocol/gkm.proto",
			message: "GkmHint",
			field:   repeated,
			want:    "GkmHint.stray_ids has no stated width",
		},
	}
	fill := func(files *protoregistry.Files, name string) (*dynamicpb.Message, error) {
		descriptor, err := files.FindDescriptorByName(protoreflect.FullName(testProtoPackage + "." + name))
		if err != nil {
			t.Fatal(err)
		}
		message := dynamicpb.NewMessage(descriptor.(protoreflect.MessageDescriptor))
		return message, testFillToWidths(message, testFieldWidths)
	}
	for _, c := range cases {
		files := testPlantedFiles(t, func(fileProtos testFileProtos) {
			planted := testPlantedMessage(t, fileProtos, c.path, c.message)
			planted.Field = append(planted.Field, c.field)
		})
		_, err := fill(files, c.message)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: wanted %q, got %v", c.message, c.want, err)
		}
	}
	// The fill reaches a nested message, here through DirectoryNotice.decisions.
	files := testPlantedFiles(t, func(fileProtos testFileProtos) {
		planted := testPlantedMessage(t, fileProtos, "protocol/directory.proto", "DecisionRef")
		planted.Field = append(planted.Field, testNewField("note", 4, stringKind))
	})
	if _, err := fill(files, "DirectoryNotice"); err == nil || !strings.Contains(err.Error(), "DecisionRef.note") {
		t.Errorf("a nested message's new field: %v", err)
	}

	// A number takes its full width: a varint field is ten bytes and its tag, which unset would be none.
	control, err := fill(testPlantedFiles(t, func(testFileProtos) {}), "GkmHint")
	if err != nil {
		t.Fatal(err)
	}
	planted, err := fill(testPlantedFiles(t, func(fileProtos testFileProtos) {
		message := testPlantedMessage(t, fileProtos, "protocol/gkm.proto", "GkmHint")
		message.Field = append(message.Field, testNewField("count", 5, descriptorpb.FieldDescriptorProto_TYPE_UINT64))
	}), "GkmHint")
	if err != nil {
		t.Fatal(err)
	}
	if grown := testSize(t, planted) - testSize(t, control); grown != 11 {
		t.Errorf("a new uint64 added %d B", grown)
	}

	// Every field of the real messages reaches the wire, width 0's aside, so a fill that stopped early cannot pass.
	for _, message := range []proto.Message{&SocketHint{}, &GkmHint{}, &EvsHeadChanged{}, &DirectoryNotice{}} {
		if err := testFillToWidths(message.ProtoReflect(), testFieldWidths); err != nil {
			t.Fatal(err)
		}
		set := 0
		message.ProtoReflect().Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool {
			set++
			return true
		})
		descriptor := message.ProtoReflect().Descriptor()
		if set != descriptor.Fields().Len() {
			t.Errorf("%s has %d of %d fields set", descriptor.Name(), set, descriptor.Fields().Len())
		}
	}
}
