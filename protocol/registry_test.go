// §6.11's registries, read from what ships: §22.5's lint over the released descriptors, the zero rule, and
// the number ranges MessageType keeps. The numbers themselves are descriptor_test.go's and the fences'.

package protocol

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Messages a oneof may stay in, by full name. Q-TEST-6 leaves this empty in v0, and a name here needs a
// reason a hot-path decode can pay for.
var testOneofAllowlist = []protoreflect.FullName{}

// Every message under roots, whether a field carries it or it is declared inside one, across files and
// through cycles and map values, that holds a oneof and is not in allowlist. walked reports what was read.
func testOneofFindings(roots []protoreflect.MessageDescriptor, allowlist []protoreflect.FullName) (findings []protoreflect.FullName, walked map[protoreflect.FullName]bool) {
	walked = map[protoreflect.FullName]bool{}
	var walk func(message protoreflect.MessageDescriptor)
	walk = func(message protoreflect.MessageDescriptor) {
		if walked[message.FullName()] {
			return
		}
		walked[message.FullName()] = true
		if message.Oneofs().Len() != 0 && !slices.Contains(allowlist, message.FullName()) {
			findings = append(findings, message.FullName())
		}
		fields := message.Fields()
		for i := range fields.Len() {
			if fieldMessage := fields.Get(i).Message(); fieldMessage != nil {
				walk(fieldMessage)
			}
		}
		messages := message.Messages()
		for i := range messages.Len() {
			walk(messages.Get(i))
		}
	}
	for _, root := range roots {
		walk(root)
	}
	slices.Sort(findings)
	return findings, walked
}

// Each message a file declares at its top level.
func testFileMessages(file protoreflect.FileDescriptor) []protoreflect.MessageDescriptor {
	messages := file.Messages()
	roots := make([]protoreflect.MessageDescriptor, 0, messages.Len())
	for i := range messages.Len() {
		roots = append(roots, messages.Get(i))
	}
	return roots
}

// §6.11 and §22.5: no oneof in envelope, stream or push messages or anything they carry. The roots are every
// message those files declare, so a new one joins by being declared, and the walk reads the descriptors
// compiled in, which are what ship.
func TestNoOneofFromEnvelopeStreamAndPushRoots(t *testing.T) {
	if len(testOneofAllowlist) != 0 {
		t.Errorf("the allowlist is empty in v0, not %v", testOneofAllowlist)
	}
	roots := []protoreflect.MessageDescriptor{}
	for _, path := range []string{"protocol/envelope.proto", "protocol/stream.proto", "protocol/push.proto"} {
		messages := testFileMessages(testFile(t, path))
		if len(messages) == 0 {
			t.Fatalf("%s declares no message", path)
		}
		roots = append(roots, messages...)
	}
	findings, walked := testOneofFindings(roots, testOneofAllowlist)
	for _, name := range findings {
		t.Errorf("%s holds a oneof", name)
	}
	// the walk must reach what those roots name, across files, or it proves less than it says
	for _, name := range []string{"Envelope", "Chunk", "HeadCheck", "UnverifiedPin", "AuthPin", "StreamOpen", "PollResponse", "TopicVersion"} {
		if !walked[protoreflect.FullName(testProtoPackage+"."+name)] {
			t.Errorf("the walk never reached %s", name)
		}
	}
}

// Plants a oneof everywhere the lint says it looks, because a lint that passes the real files says
// nothing about what it would catch.
func TestOneofLintCatchesPlantedDeclarations(t *testing.T) {
	message := func(name string, fields ...*descriptorpb.FieldDescriptorProto) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{Name: proto.String(name), Field: fields}
	}
	carrying := func(name string, target string, number int32) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{
			Name:     proto.String(name),
			Number:   proto.Int32(number),
			Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
			TypeName: proto.String(".planted." + target),
		}
	}
	withOneof := func(name string) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{
			Name: proto.String(name),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:       proto.String("member"),
				Number:     proto.Int32(1),
				Label:      descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:       descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum(),
				OneofIndex: proto.Int32(0),
			}},
			OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("choice")}},
		}
	}
	mapEntry := &descriptorpb.DescriptorProto{
		Name:    proto.String("ValuesEntry"),
		Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
		Field: []*descriptorpb.FieldDescriptorProto{
			{
				Name:   proto.String("key"),
				Number: proto.Int32(1),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			},
			carrying("value", "InMapValue", 2),
		},
	}
	mapped := message("Mapped", &descriptorpb.FieldDescriptorProto{
		Name:     proto.String("values"),
		Number:   proto.Int32(1),
		Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
		Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
		TypeName: proto.String(".planted.Mapped.ValuesEntry"),
	})
	mapped.NestedType = []*descriptorpb.DescriptorProto{mapEntry}
	nesting := message("Nesting")
	nesting.NestedType = []*descriptorpb.DescriptorProto{withOneof("Nested")}

	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("protocol/planted.proto"),
		Package: proto.String("planted"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			message("Clean", carrying("self", "Clean", 1)),
			withOneof("Direct"),
			message("Carrying", carrying("carried", "InCarried", 1)),
			withOneof("InCarried"),
			mapped,
			withOneof("InMapValue"),
			nesting,
			message("CycleA", carrying("next", "CycleB", 1)),
			{
				Name: proto.String("CycleB"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:       proto.String("member"),
						Number:     proto.Int32(1),
						Label:      descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:       descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum(),
						OneofIndex: proto.Int32(0),
					},
					carrying("back", "CycleA", 2),
				},
				OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("choice")}},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	messages := file.Messages()
	cases := []struct {
		root      protoreflect.Name
		allowlist []protoreflect.FullName
		want      []protoreflect.FullName
	}{
		{root: "Clean", want: nil},
		{root: "Direct", want: []protoreflect.FullName{"planted.Direct"}},
		{root: "Direct", allowlist: []protoreflect.FullName{"planted.Direct"}, want: nil},
		{root: "Carrying", want: []protoreflect.FullName{"planted.InCarried"}},
		{root: "Mapped", want: []protoreflect.FullName{"planted.InMapValue"}},
		{root: "Nesting", want: []protoreflect.FullName{"planted.Nesting.Nested"}},
		{root: "CycleA", want: []protoreflect.FullName{"planted.CycleB"}},
	}
	for _, c := range cases {
		findings, _ := testOneofFindings([]protoreflect.MessageDescriptor{messages.ByName(c.root)}, c.allowlist)
		if !slices.Equal(findings, c.want) {
			t.Errorf("from %s: found %v, want %v", c.root, findings, c.want)
		}
	}
}

// Every enum in this package that names a code, by its name, so a new one joins by being declared.
func testCodeEnums(t *testing.T) []protoreflect.EnumDescriptor {
	enums := []protoreflect.EnumDescriptor{}
	protoregistry.GlobalFiles.RangeFilesByPackage(testProtoPackage, func(file protoreflect.FileDescriptor) bool {
		fileEnums := file.Enums()
		for i := range fileEnums.Len() {
			if strings.HasSuffix(string(fileEnums.Get(i).Name()), "Code") {
				enums = append(enums, fileEnums.Get(i))
			}
		}
		return true
	})
	// §6.5, §6.7 and §6.11 name these, so finding fewer means the filter broke
	if len(enums) < 5 {
		t.Fatalf("found %d code enums", len(enums))
	}
	return enums
}

// §6.11 and D-PROTO-20: every code starts at UNSPECIFIED 0, so a default-constructed one can never read
// as retry, drain or success. ErrorCode is the one exception, with an OK no sender sets.
func TestEveryCodeStartsAtAZeroNoSenderSets(t *testing.T) {
	for _, enum := range testCodeEnums(t) {
		zero := enum.Values().ByNumber(0)
		if zero == nil {
			t.Errorf("%s has no 0", enum.Name())
			continue
		}
		if enum.Name() == "ErrorCode" {
			if zero.Name() != "ERR_OK" {
				t.Errorf("ErrorCode's 0 is %s", zero.Name())
			}
			continue
		}
		if !strings.HasSuffix(string(zero.Name()), "_UNSPECIFIED") {
			t.Errorf("%s's 0 is %s", enum.Name(), zero.Name())
		}
	}
}

// §6.11: services 0x80-0xFF are unreleased experiments, so no released number sits there, and 0 is no
// message. A value's service byte has to be one the registry gives an owner.
func TestMessageTypesStayInReleasedServices(t *testing.T) {
	services := []int32{0x00, 0x01, 0x02, 0x10, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x1A, 0x1B}
	for number, name := range MessageType_name {
		if number == 0 {
			if name != "MESSAGE_TYPE_NONE" {
				t.Errorf("0 is %s", name)
			}
			continue
		}
		service := number >> 8
		if 0x80 <= service {
			t.Errorf("%s sits in the experiments' range", name)
		}
		if !slices.Contains(services, service) {
			t.Errorf("%s is in service %#x, which §6.11 gives no owner", name, service)
		}
		if number&0xFF == 0 {
			t.Errorf("%s has message number 0", name)
		}
	}
}
