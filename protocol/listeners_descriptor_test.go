// listeners.proto held to the numbers written here (LSTN-M13-01): design_fence_test.go holds its declarations to
// testUnfencedFence, which moves with the design until the format freezes, so this keeps the fields and values as
// written, and a change to both at once still fails. The file's JSON form is the root's (listeners_file.go), whose tests
// hold its keys and words.

package protocol

import (
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const testListenersProtoPath = "protocol/listeners.proto"

// Each message's fields in declaration order: the file's in §26.6's example's key order, then v4_uncertain and the
// plan's, the ask's as §26.8 names them (QD-1249).
var testListenersFields = map[protoreflect.Name][]string{
	"ListenersEntry": {
		"1 kind ListenersEntryKind", "2 proto ListenersProtocol", "3 port uint32", "4 bind string", "5 target string",
		"6 to string", "7 desc string", "8 desc_by ListenersDescriptionSource", "9 until int64", "10 shared bool",
		"11 v4_uncertain bool", "12 name string", "13 audience AclAudience", "14 shadowed bool",
		"15 own_view ListenersOwnView",
	},
	"ListenersFile": {
		"1 v uint32", "2 sidecar bytes", "3 updated int64", "4 withheld ListenersWithheld", "5 truncated bool",
		"6 entries repeated ListenersEntry",
	},
	"ListenersRequest": {"1 device_scope bytes", "2 include_own_view bool"},
	"ListenersResult":  {"1 file bytes", "2 own_view_entries repeated ListenersEntry"},
}

// Each enum's values in declaration order, zero unspecified.
var testListenersValues = map[protoreflect.Name][]string{
	"ListenersEntryKind": {
		"0 LISTENERS_ENTRY_KIND_UNSPECIFIED", "1 LISTENERS_ENTRY_KIND_SOCKET", "2 LISTENERS_ENTRY_KIND_MAP",
		"3 LISTENERS_ENTRY_KIND_FORWARD", "4 LISTENERS_ENTRY_KIND_SOCK", "5 LISTENERS_ENTRY_KIND_TLS",
		"6 LISTENERS_ENTRY_KIND_SSH",
	},
	"ListenersProtocol": {"0 LISTENERS_PROTOCOL_UNSPECIFIED", "1 LISTENERS_PROTOCOL_TCP", "2 LISTENERS_PROTOCOL_UDP"},
	"ListenersDescriptionSource": {
		"0 LISTENERS_DESCRIPTION_SOURCE_UNSPECIFIED", "1 LISTENERS_DESCRIPTION_SOURCE_LABEL",
		"2 LISTENERS_DESCRIPTION_SOURCE_PROGRAM", "3 LISTENERS_DESCRIPTION_SOURCE_OTHER_USER",
		"4 LISTENERS_DESCRIPTION_SOURCE_SYSTEM", "5 LISTENERS_DESCRIPTION_SOURCE_TARGET_PROGRAM",
		"6 LISTENERS_DESCRIPTION_SOURCE_TARGET", "7 LISTENERS_DESCRIPTION_SOURCE_FIXED",
	},
	"ListenersWithheld": {
		"0 LISTENERS_WITHHELD_UNSPECIFIED", "1 LISTENERS_WITHHELD_DISCLOSURE", "2 LISTENERS_WITHHELD_DEVICE",
		"3 LISTENERS_WITHHELD_NETWORK_ACK", "4 LISTENERS_WITHHELD_HIDDEN", "5 LISTENERS_WITHHELD_NETWORK",
	},
	"ListenersOwnView": {
		"0 LISTENERS_OWN_VIEW_UNSPECIFIED", "1 LISTENERS_OWN_VIEW_LOOPBACK", "2 LISTENERS_OWN_VIEW_ONE_ADDRESS",
		"3 LISTENERS_OWN_VIEW_IPV6_ONLY", "4 LISTENERS_OWN_VIEW_DAEMON", "5 LISTENERS_OWN_VIEW_HIDDEN",
		"6 LISTENERS_OWN_VIEW_CONTAINER",
	},
}

// A field as listed: number, name, then its message's or enum's name or its kind, "repeated " first for a list.
func testListenersFieldLine(field protoreflect.FieldDescriptor) string {
	line := fmt.Sprintf("%d %s ", field.Number(), field.Name())
	if field.IsList() {
		line += "repeated "
	}
	switch {
	case field.Message() != nil:
		return line + string(field.Message().Name())
	case field.Enum() != nil:
		return line + string(field.Enum().Name())
	}
	return line + field.Kind().String()
}

// The fields and values as listed, each at its number, nothing else in the file: no oneof, no nested declaration, no
// reservation, no proto3 optional, every enum's zero its unspecified value.
func TestListenersDescriptor(t *testing.T) {
	file := testFile(t, testListenersProtoPath)
	messages := file.Messages()
	if messages.Len() != len(testListenersFields) {
		t.Errorf("%s declares %d messages, and %d are listed", testListenersProtoPath, messages.Len(), len(testListenersFields))
	}
	for i := range messages.Len() {
		message := messages.Get(i)
		want, ok := testListenersFields[message.Name()]
		if !ok {
			t.Errorf("%s is not listed", message.Name())
			continue
		}
		got := []string{}
		for j := range message.Fields().Len() {
			field := message.Fields().Get(j)
			got = append(got, testListenersFieldLine(field))
			if field.HasPresence() && field.Message() == nil {
				t.Errorf("%s.%s has explicit presence", message.Name(), field.Name())
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", message.Name(), got, want)
		}
		if message.Oneofs().Len() != 0 || message.Messages().Len() != 0 || message.Enums().Len() != 0 {
			t.Errorf("%s holds a oneof or nests a declaration", message.Name())
		}
		if message.ReservedRanges().Len() != 0 || message.ReservedNames().Len() != 0 {
			t.Errorf("%s reserves numbers", message.Name())
		}
	}
	enums := file.Enums()
	if enums.Len() != len(testListenersValues) {
		t.Errorf("%s declares %d enums, and %d are listed", testListenersProtoPath, enums.Len(), len(testListenersValues))
	}
	for i := range enums.Len() {
		enum := enums.Get(i)
		want, ok := testListenersValues[enum.Name()]
		if !ok {
			t.Errorf("%s is not listed", enum.Name())
			continue
		}
		got := []string{}
		for j := range enum.Values().Len() {
			value := enum.Values().Get(j)
			got = append(got, fmt.Sprintf("%d %s", value.Number(), value.Name()))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", enum.Name(), got, want)
		}
		if zero := enum.Values().ByNumber(0); zero == nil || zero.Name() != protoreflect.Name(fmt.Sprintf("%s_UNSPECIFIED", testListenersEnumPrefix(enum))) {
			t.Errorf("%s's zero is not its unspecified value", enum.Name())
		}
	}
}

// An enum's value prefix: its name in upper snake case.
func testListenersEnumPrefix(enum protoreflect.EnumDescriptor) string {
	prefix := []byte{}
	for i, r := range string(enum.Name()) {
		if 'A' <= r && r <= 'Z' && i != 0 {
			prefix = append(prefix, '_')
		}
		if 'a' <= r && r <= 'z' {
			r -= 'a' - 'A'
		}
		prefix = append(prefix, byte(r))
	}
	return string(prefix)
}

// Each message round-trips through a deterministic marshal: what a host answers is what its asker decodes, field for
// field, an own-view entry's reason and address among them.
func TestListenersMessagesRoundTrip(t *testing.T) {
	sidecarId := []byte("sidecar-test-016")
	socket := &ListenersEntry{
		Kind: ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, Proto: ListenersProtocol_LISTENERS_PROTOCOL_TCP, Port: 5432,
		Bind: "0.0.0.0", Desc: "postgres", DescBy: ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_PROGRAM,
	}
	mapped := &ListenersEntry{
		Kind: ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP, Proto: ListenersProtocol_LISTENERS_PROTOCOL_TCP, Port: 8000,
		Target: "192.0.2.20:8000", Desc: "nas admin", DescBy: ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_LABEL,
		Until: 1764547200000,
	}
	published := &ListenersEntry{
		Kind: ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS, Proto: ListenersProtocol_LISTENERS_PROTOCOL_TCP, Port: 443,
		Name: "shop", Target: "127.0.0.1:3000", Audience: AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, Until: 1764547200000,
	}
	own := &ListenersEntry{
		Kind: ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, Proto: ListenersProtocol_LISTENERS_PROTOCOL_TCP, Port: 9222,
		Bind: "127.0.0.1", Desc: "chrome", DescBy: ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_PROGRAM,
		OwnView: ListenersOwnView_LISTENERS_OWN_VIEW_LOOPBACK, Shared: true,
	}
	windows := &ListenersEntry{
		Kind: ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, Proto: ListenersProtocol_LISTENERS_PROTOCOL_TCP, Port: 3389,
		Bind: "::", V4Uncertain: true, Shadowed: true, Desc: "a system program",
		DescBy: ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_SYSTEM,
	}
	messages := []proto.Message{
		socket, mapped, published, own, windows,
		&ListenersFile{
			V: 1, Sidecar: sidecarId, Updated: 1763906700000, Truncated: true,
			Entries: []*ListenersEntry{mapped, published, socket, windows},
		},
		&ListenersFile{V: 1, Sidecar: sidecarId, Updated: 1763906700000, Withheld: ListenersWithheld_LISTENERS_WITHHELD_NETWORK_ACK},
		&ListenersRequest{DeviceScope: sidecarId, IncludeOwnView: true},
		&ListenersResult{File: []byte(`{"v":1}`), OwnViewEntries: []*ListenersEntry{own}},
	}
	for _, message := range messages {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		decoded := message.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(encoded, decoded); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(message, decoded) {
			t.Errorf("decoded %v, want %v", decoded, message)
		}
		again, err := proto.MarshalOptions{Deterministic: true}.Marshal(decoded)
		if err != nil || string(again) != string(encoded) {
			t.Errorf("%s's marshal is not stable: %x and %x, %v", message.ProtoReflect().Descriptor().Name(), encoded, again, err)
		}
	}
}
