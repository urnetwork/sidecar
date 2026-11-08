// Every fenced proto block in DESIGN.md, and what the design writes any other way, read against what this package
// registers, so a wire that leaves the design fails here. testWireDifferences says exactly what is held. Whatever the
// package declares beyond the fences is written out in testUnfencedFence, with where the design writes it, which is
// where a reviewer reads what this repository added to the design's wire, and a field an owner's answer adds to a
// fenced message before design-records folds it in is in testFenceAdditions, with the question that holds the answer.

package protocol

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Where DESIGN.md is from this directory. A release branch keeps it at the repository's top, beside
// the module moved into v2026/ (§4.9), so there it sits one directory further up.
var testDesignPaths = []string{"../DESIGN.md", "../../DESIGN.md"}

// Written so a fence's string, identifier, number and punctuation each stay one token.
var testFenceToken = regexp.MustCompile(`"[^"]*"|[A-Za-z_][A-Za-z0-9_.]*|0x[0-9A-Fa-f]+|[0-9]+|[{};=,<>]`)

// The file a fence's comment names.
var testFenceFile = regexp.MustCompile(`sidecar/protocol/[a-z/]*[a-z]+\.proto`)

// The opening of a message or enum, and its name.
var testFenceDeclaration = regexp.MustCompile(`\b(?:message|enum)\s+([A-Za-z_][A-Za-z0-9_]*)`)

// Where a fence that names no file belongs, by its first declaration: the section's own wire for §6, §11 and §17, and
// the plans' names for socket, tls, smtp and mail, which §4.4's tree does not list.
var testFirstDeclarationFiles = map[string]string{
	"Envelope":         "protocol/envelope.proto",
	"StreamOpen":       "protocol/stream.proto",
	"SocketHint":       "protocol/socket.proto",
	"SocketTicket":     "protocol/socket.proto",
	"EvsHead":          "protocol/evs.proto",
	"TlsEdgeOpen":      "protocol/tls.proto",
	"SmtpPreamble":     "protocol/smtp.proto",
	"MailIngress":      "protocol/mail.proto",
	"MailAuthEvidence": "protocol/mail.proto",
	"BridgeRows":       "protocol/bridge/bridge.proto",
	"WindowDelegation": "protocol/bridge/bridge.proto",
}

// A field as a fence writes it. A map's typeName reads map<key,value>.
type testFenceField struct {
	name     string
	number   int32
	typeName string
	repeated bool
}

// A message as a fence writes it, with the file that fence places it in.
type testFenceMessage struct {
	path            string
	fields          []testFenceField
	reservedNumbers []int32
	reservedNames   []string
}

// An enum as a fence writes it, with the file that fence places it in.
type testFenceEnum struct {
	path            string
	values          map[string]int32
	reservedNumbers []int32
	reservedNames   []string
}

// Every declaration the fences write, by name.
type testFences struct {
	messages map[string]*testFenceMessage
	enums    map[string]*testFenceEnum
}

// Reads a `reserved` statement's numbers and names, leaving tokens at the one after its semicolon.
func testParseReserved(t *testing.T, tokens []string) (rest []string, numbers []int32, names []string) {
	for tokens[0] != ";" {
		token := tokens[0]
		tokens = tokens[1:]
		switch {
		case token == ",":
		case token == "to":
			upper := testParseNumber(t, tokens[0])
			tokens = tokens[1:]
			for number := numbers[len(numbers)-1] + 1; number <= upper; number++ {
				numbers = append(numbers, number)
			}
		case strings.HasPrefix(token, `"`):
			names = append(names, strings.Trim(token, `"`))
		default:
			numbers = append(numbers, testParseNumber(t, token))
		}
	}
	return tokens[1:], numbers, names
}

// A fence's number, decimal or hex.
func testParseNumber(t *testing.T, token string) int32 {
	number, err := strconv.ParseInt(token, 0, 32)
	if err != nil {
		t.Fatalf("number %q: %v", token, err)
	}
	return int32(number)
}

// One fence's messages and enums, read into fences. Fences hold no nesting, oneof or option inside a body, so
// anything else stops the test rather than being skipped. A declaration sits in the file the nearest comment at or
// above it names; failing that, the first file the fence names, and failing that testFirstDeclarationFiles.
func testParseFence(t *testing.T, fences *testFences, fence string) {
	var source strings.Builder
	declarationPaths := map[string]string{}
	firstDeclaration := ""
	firstPath := ""
	path := ""
	for line := range strings.SplitSeq(fence, "\n") {
		code, comment, _ := strings.Cut(line, "//")
		source.WriteString(code + "\n")
		if file := testFenceFile.FindString(comment); file != "" {
			path = strings.TrimPrefix(file, "sidecar/")
			if firstPath == "" {
				firstPath = path
			}
		}
		for _, declaration := range testFenceDeclaration.FindAllStringSubmatch(code, -1) {
			declarationPaths[declaration[1]] = path
			if firstDeclaration == "" {
				firstDeclaration = declaration[1]
			}
		}
	}
	if firstPath == "" {
		firstPath = testFirstDeclarationFiles[firstDeclaration]
	}
	if firstPath == "" {
		t.Fatalf("the fence opening with %s names no file, and testFirstDeclarationFiles does not place it", firstDeclaration)
	}
	pathOf := func(name string) string {
		if declarationPaths[name] != "" {
			return declarationPaths[name]
		}
		return firstPath
	}

	tokens := testFenceToken.FindAllString(source.String(), -1)
	for len(tokens) > 0 {
		switch tokens[0] {
		case "syntax", "package", "import", "option":
			end := slices.Index(tokens, ";")
			tokens = tokens[end+1:]
		case "message":
			name := tokens[1]
			if fences.messages[name] != nil {
				t.Errorf("message %s is written twice", name)
			}
			message := &testFenceMessage{path: pathOf(name)}
			fences.messages[name] = message
			tokens = tokens[3:]
			for tokens[0] != "}" {
				if tokens[0] == "reserved" {
					var numbers []int32
					var names []string
					tokens, numbers, names = testParseReserved(t, tokens[1:])
					message.reservedNumbers = append(message.reservedNumbers, numbers...)
					message.reservedNames = append(message.reservedNames, names...)
					continue
				}
				field := testFenceField{}
				if tokens[0] == "repeated" {
					field.repeated = true
					tokens = tokens[1:]
				}
				field.typeName = tokens[0]
				tokens = tokens[1:]
				if field.typeName == "map" {
					field.typeName = "map<" + tokens[1] + "," + tokens[3] + ">"
					tokens = tokens[5:]
				}
				field.name = tokens[0]
				if tokens[1] != "=" || tokens[3] != ";" {
					t.Fatalf("%s.%s: unexpected %v", name, field.name, tokens[:4])
				}
				field.number = testParseNumber(t, tokens[2])
				tokens = tokens[4:]
				message.fields = append(message.fields, field)
			}
			tokens = tokens[1:]
		case "enum":
			name := tokens[1]
			if fences.enums[name] != nil {
				t.Errorf("enum %s is written twice", name)
			}
			enum := &testFenceEnum{path: pathOf(name), values: map[string]int32{}}
			fences.enums[name] = enum
			tokens = tokens[3:]
			for tokens[0] != "}" {
				if tokens[0] == "reserved" {
					var numbers []int32
					var names []string
					tokens, numbers, names = testParseReserved(t, tokens[1:])
					enum.reservedNumbers = append(enum.reservedNumbers, numbers...)
					enum.reservedNames = append(enum.reservedNames, names...)
					continue
				}
				if tokens[1] != "=" || tokens[3] != ";" {
					t.Fatalf("%s.%s: unexpected %v", name, tokens[0], tokens[:4])
				}
				enum.values[tokens[0]] = testParseNumber(t, tokens[2])
				tokens = tokens[4:]
			}
			tokens = tokens[1:]
		default:
			t.Fatalf("a fence holds %q where a declaration should start", tokens[0])
		}
	}
}

// DESIGN.md's bytes, from beside the module or, on a release branch, from one directory further up.
func testReadDesign(t testing.TB) []byte {
	design, err := os.ReadFile(testDesignPaths[0])
	if errors.Is(err, os.ErrNotExist) {
		design, err = os.ReadFile(testDesignPaths[1])
	}
	if err != nil {
		t.Fatalf("this test needs the design beside the module: %v", err)
	}
	return design
}

// Every fenced proto block in DESIGN.md, then testUnfencedFence, read into one set of declarations, with
// testFenceAdditions' fields and testFenceValueAdditions' values joining the fences they extend. A declaration that
// later gains a fence is then written twice, which says to take it out of testUnfencedFence, and an added field or
// value the design comes to write fails until its line leaves its list.
func testReadFences(t *testing.T) *testFences {
	design := testReadDesign(t)
	fences := &testFences{messages: map[string]*testFenceMessage{}, enums: map[string]*testFenceEnum{}}
	var fence *strings.Builder
	count := 0
	for line := range strings.SplitSeq(string(design), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case fence == nil && trimmed == "```proto":
			fence = &strings.Builder{}
		case fence != nil && trimmed == "```":
			testParseFence(t, fences, fence.String())
			fence = nil
			count++
		case fence != nil:
			fence.WriteString(line + "\n")
		}
	}
	// A parser that found nothing would pass everything below.
	if count < 27 || len(fences.messages) < 120 {
		t.Fatalf("found %d fences and %d messages, too few to have read the design", count, len(fences.messages))
	}
	testParseFence(t, fences, testUnfencedFence)
	for _, addition := range testFenceAdditions {
		message := fences.messages[addition.message]
		if message == nil {
			t.Errorf("%s gains %s by %s, and no fence writes that message", addition.message, addition.field.name, addition.question)
			continue
		}
		written := slices.ContainsFunc(message.fields, func(field testFenceField) bool {
			return field.name == addition.field.name || field.number == addition.field.number
		})
		if written || slices.Contains(message.reservedNumbers, addition.field.number) {
			t.Errorf("the design now writes %s.%s or its number %d: drop its line from testFenceAdditions (%s)", addition.message, addition.field.name, addition.field.number, addition.question)
			continue
		}
		message.fields = append(message.fields, addition.field)
	}
	for _, addition := range testFenceValueAdditions {
		enum := fences.enums[addition.enum]
		if enum == nil {
			t.Errorf("%s gains %s by %s, and no fence writes that enum", addition.enum, addition.name, addition.question)
			continue
		}
		_, written := enum.values[addition.name]
		for _, number := range enum.values {
			written = written || number == addition.number
		}
		if written || slices.Contains(enum.reservedNumbers, addition.number) {
			t.Errorf("the design now writes %s.%s or its number %#x: drop its line from testFenceValueAdditions (%s)", addition.enum, addition.name, addition.number, addition.question)
			continue
		}
		enum.values[addition.name] = addition.number
	}
	return fences
}

// A message's reserved ranges, each number written out.
func testReservedNumbers(ranges protoreflect.FieldRanges) []int32 {
	numbers := []int32{}
	for i := range ranges.Len() {
		for number := ranges.Get(i)[0]; number < ranges.Get(i)[1]; number++ {
			numbers = append(numbers, int32(number))
		}
	}
	return numbers
}

// An enum's reserved ranges, each number written out.
func testEnumReservedNumbers(ranges protoreflect.EnumRanges) []int32 {
	numbers := []int32{}
	for i := range ranges.Len() {
		// An enum range's end is inclusive, where a message's is not.
		for number := ranges.Get(i)[0]; number <= ranges.Get(i)[1]; number++ {
			numbers = append(numbers, int32(number))
		}
	}
	return numbers
}

// A sorted copy, never nil, so slices.Equal compares two empty lists alike.
func testSorted(numbers []int32) []int32 {
	sorted := slices.Clone(numbers)
	if sorted == nil {
		sorted = []int32{}
	}
	slices.Sort(sorted)
	return sorted
}

// How files differ from fences, in both directions, over every file of the package, so nothing a file adds goes
// unread. A declaration matches its fence in the file that holds it, each field's number, name, type and cardinality,
// each enum value and each reservation. Beyond that it may hold no option, optional field, oneof, nested declaration
// or extension, because no fence writes one and each can change an encoding or add to the wire without touching a
// number; a map field's entry message is the one nesting allowed. A file holds no service, no extension, and no
// option but go_package, which a release rewrites. Comments, declaration order, imports and JSON names are not
// compared: none reaches the wire. SignedType's fence is its zero value and a comment, because owners add values with
// their formats (§6.11), so its values need only be contained, and signed_registry_test.go holds the rest.
func testWireDifferences(fences *testFences, files *protoregistry.Files) []string {
	differences := []string{}
	report := func(format string, arguments ...any) {
		differences = append(differences, fmt.Sprintf(format, arguments...))
	}
	typeName := func(field protoreflect.FieldDescriptor) string {
		switch field.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			return string(field.Message().Name())
		case protoreflect.EnumKind:
			return string(field.Enum().Name())
		}
		return field.Kind().String()
	}
	compareReserved := func(name string, numbers []int32, names protoreflect.Names, wantNumbers []int32, wantNames []string) {
		if !slices.Equal(testSorted(numbers), testSorted(wantNumbers)) {
			report("%s reserves %v, and its fence %v", name, numbers, wantNumbers)
		}
		if names.Len() != len(wantNames) {
			report("%s reserves %d names, and its fence %d", name, names.Len(), len(wantNames))
		}
		for _, wantName := range wantNames {
			if !names.Has(protoreflect.Name(wantName)) {
				report("%s does not reserve %s", name, wantName)
			}
		}
	}
	compareMessage := func(name string, fence *testFenceMessage, message protoreflect.MessageDescriptor) {
		fields := message.Fields()
		written := map[protoreflect.Name]bool{}
		for _, want := range fence.fields {
			written[protoreflect.Name(want.name)] = true
			field := fields.ByName(protoreflect.Name(want.name))
			if field == nil {
				report("%s.%s is written and not declared", name, want.name)
				continue
			}
			if int32(field.Number()) != want.number {
				report("%s.%s is %d, and its fence writes %d", name, want.name, field.Number(), want.number)
			}
			got := typeName(field)
			if field.IsMap() {
				got = "map<" + typeName(field.MapKey()) + "," + typeName(field.MapValue()) + ">"
			}
			if got != want.typeName {
				report("%s.%s is %s, and its fence writes %s", name, want.name, got, want.typeName)
			}
			if field.IsList() != want.repeated {
				report("%s.%s repeated is %t, and its fence writes %t", name, want.name, field.IsList(), want.repeated)
			}
			if field.HasOptionalKeyword() {
				report("%s.%s is optional, which changes its encoding", name, want.name)
			}
			if proto.Size(field.Options()) != 0 {
				report("%s.%s sets options: %v", name, want.name, field.Options())
			}
		}
		for i := range fields.Len() {
			if !written[fields.Get(i).Name()] {
				report("%s.%s is declared and not written", name, fields.Get(i).Name())
			}
		}
		compareReserved(
			name, testReservedNumbers(message.ReservedRanges()), message.ReservedNames(),
			fence.reservedNumbers, fence.reservedNames,
		)
		if proto.Size(message.Options()) != 0 {
			report("%s sets options: %v", name, message.Options())
		}
		if message.Oneofs().Len() != 0 {
			report("%s holds a oneof", name)
		}
		nested := message.Messages()
		for i := range nested.Len() {
			if !nested.Get(i).IsMapEntry() {
				report("%s nests message %s", name, nested.Get(i).Name())
			}
		}
		if message.Enums().Len() != 0 {
			report("%s nests enum %s", name, message.Enums().Get(0).Name())
		}
		if message.Extensions().Len() != 0 || message.ExtensionRanges().Len() != 0 {
			report("%s holds an extension", name)
		}
	}
	compareEnum := func(name string, fence *testFenceEnum, enum protoreflect.EnumDescriptor) {
		values := enum.Values()
		for valueName, number := range fence.values {
			value := values.ByName(protoreflect.Name(valueName))
			if value == nil {
				report("%s.%s is written and not declared", name, valueName)
				continue
			}
			if int32(value.Number()) != number {
				report("%s.%s is %d, and its fence writes %d", name, valueName, value.Number(), number)
			}
		}
		for i := range values.Len() {
			value := values.Get(i)
			if _, ok := fence.values[string(value.Name())]; !ok && name != "SignedType" {
				report("%s.%s is declared and not written", name, value.Name())
			}
			if proto.Size(value.Options()) != 0 {
				report("%s.%s sets options: %v", name, value.Name(), value.Options())
			}
		}
		compareReserved(
			name, testEnumReservedNumbers(enum.ReservedRanges()), enum.ReservedNames(),
			fence.reservedNumbers, fence.reservedNames,
		)
		if proto.Size(enum.Options()) != 0 {
			report("%s sets options: %v", name, enum.Options())
		}
	}

	declared := map[string]bool{}
	files.RangeFilesByPackage(testProtoPackage, func(file protoreflect.FileDescriptor) bool {
		path := file.Path()
		if file.Services().Len() != 0 {
			report("%s declares service %s", path, file.Services().Get(0).Name())
		}
		if file.Extensions().Len() != 0 {
			report("%s declares extension %s", path, file.Extensions().Get(0).Name())
		}
		options := proto.Clone(file.Options()).(*descriptorpb.FileOptions)
		options.GoPackage = nil
		if proto.Size(options) != 0 {
			report("%s sets options: %v", path, options)
		}
		messages := file.Messages()
		for i := range messages.Len() {
			message := messages.Get(i)
			name := string(message.Name())
			declared[name] = true
			fence := fences.messages[name]
			if fence == nil {
				report("%s declares message %s, which no fence writes: add it to testUnfencedFence", path, name)
				continue
			}
			if fence.path != path {
				report("%s is in %s, and its fence puts it in %s", name, path, fence.path)
			}
			compareMessage(name, fence, message)
		}
		enums := file.Enums()
		for i := range enums.Len() {
			enum := enums.Get(i)
			name := string(enum.Name())
			declared[name] = true
			fence := fences.enums[name]
			if fence == nil {
				report("%s declares enum %s, which no fence writes: add it to testUnfencedFence", path, name)
				continue
			}
			if fence.path != path {
				report("%s is in %s, and its fence puts it in %s", name, path, fence.path)
			}
			compareEnum(name, fence, enum)
		}
		return true
	})
	for _, name := range slices.Sorted(maps.Keys(fences.messages)) {
		if !declared[name] {
			report("message %s is written and no file declares it", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(fences.enums)) {
		if !declared[name] {
			report("enum %s is written and no file declares it", name)
		}
	}
	return differences
}

// §4.9, and the rule that numbers stay as written.
func TestDeclarationsMatchTheirFences(t *testing.T) {
	for _, difference := range testWireDifferences(testReadFences(t), protoregistry.GlobalFiles) {
		t.Error(difference)
	}
}

// The package's files as descriptors, by path, for a test to plant faults in.
type testFileProtos map[string]*descriptorpb.FileDescriptorProto

// The package rebuilt after mutate, as protoc would have registered it: a test plants in this copy what must never
// reach the real files, because a check that passes them says nothing about what it would catch.
func testPlantedFiles(t testing.TB, mutate func(fileProtos testFileProtos)) *protoregistry.Files {
	fileProtos := testFileProtos{}
	protoregistry.GlobalFiles.RangeFilesByPackage(testProtoPackage, func(file protoreflect.FileDescriptor) bool {
		fileProtos[file.Path()] = protodesc.ToFileDescriptorProto(file)
		return true
	})
	mutate(fileProtos)
	files, err := protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: slices.Collect(maps.Values(fileProtos))})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// A planted file's message, to change in place.
func testPlantedMessage(t testing.TB, fileProtos testFileProtos, path string, name string) *descriptorpb.DescriptorProto {
	for _, message := range fileProtos[path].GetMessageType() {
		if message.GetName() == name {
			return message
		}
	}
	t.Fatalf("%s has no message %s", path, name)
	return nil
}

// A planted message's field, to change in place.
func testPlantedField(t testing.TB, message *descriptorpb.DescriptorProto, name string) *descriptorpb.FieldDescriptorProto {
	for _, field := range message.GetField() {
		if field.GetName() == name {
			return field
		}
	}
	t.Fatalf("%s has no field %s", message.GetName(), name)
	return nil
}

// A singular field to plant.
func testNewField(
	name string, number int32, kind descriptorpb.FieldDescriptorProto_Type,
) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:   proto.String(name),
		Number: proto.Int32(number),
		Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		Type:   kind.Enum(),
	}
}

// Whether a check found what a plant should make it find.
func testHasDifference(differences []string, want string) bool {
	return slices.ContainsFunc(differences, func(difference string) bool {
		return strings.Contains(difference, want)
	})
}

// Each fault a review planted by hand, and its neighbours, so what the comparison reads stays what its comment says:
// fields of a declaration no fence writes, a fenced field's encoding, nesting, placement, and the reverse walk.
func TestWireDifferencesCatchPlantedFaults(t *testing.T) {
	const (
		gkm = "protocol/gkm.proto"
		evs = "protocol/evs.proto"
	)
	bytesKind := descriptorpb.FieldDescriptorProto_TYPE_BYTES
	optional := func(message *descriptorpb.DescriptorProto, name string) {
		field := testPlantedField(t, message, name)
		field.Proto3Optional = proto.Bool(true)
		field.OneofIndex = proto.Int32(int32(len(message.OneofDecl)))
		message.OneofDecl = append(message.OneofDecl, &descriptorpb.OneofDescriptorProto{Name: proto.String("_" + name)})
	}
	dropField := func(message *descriptorpb.DescriptorProto, name string) {
		message.Field = slices.DeleteFunc(message.Field, func(field *descriptorpb.FieldDescriptorProto) bool {
			return field.GetName() == name
		})
	}
	nestedEnum := &descriptorpb.EnumDescriptorProto{
		Name:  proto.String("Stray"),
		Value: []*descriptorpb.EnumValueDescriptorProto{{Name: proto.String("STRAY_NONE"), Number: proto.Int32(0)}},
	}
	cases := []struct {
		name   string
		want   string
		mutate func(fileProtos testFileProtos)
	}{
		{
			name: "ReaderKey's numbers swapped",
			want: "ReaderKey.sidecar_id is 2",
			mutate: func(fileProtos testFileProtos) {
				message := testPlantedMessage(t, fileProtos, gkm, "ReaderKey")
				testPlantedField(t, message, "sidecar_id").Number = proto.Int32(2)
				testPlantedField(t, message, "xwing_public_key").Number = proto.Int32(1)
			},
		},
		{
			name: "ReaderKey.not_after narrowed to uint32, which cannot hold ms",
			want: "ReaderKey.not_after is uint32",
			mutate: func(fileProtos testFileProtos) {
				field := testPlantedField(t, testPlantedMessage(t, fileProtos, gkm, "ReaderKey"), "not_after")
				field.Type = descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum()
			},
		},
		{
			name: "a plaintext field added to ReaderKey",
			want: "ReaderKey.plaintext_name is declared and not written",
			mutate: func(fileProtos testFileProtos) {
				message := testPlantedMessage(t, fileProtos, gkm, "ReaderKey")
				message.Field = append(message.Field, testNewField("plaintext_name", 4, bytesKind))
			},
		},
		{
			name: "GroupForm.previous_group_id deleted",
			want: "GroupForm.previous_group_id is written and not declared",
			mutate: func(fileProtos testFileProtos) {
				dropField(testPlantedMessage(t, fileProtos, gkm, "GroupForm"), "previous_group_id")
			},
		},
		{
			name: "EvsHeadChanged.push_id renumbered",
			want: "EvsHeadChanged.push_id is 9",
			mutate: func(fileProtos testFileProtos) {
				testPlantedField(t, testPlantedMessage(t, fileProtos, evs, "EvsHeadChanged"), "push_id").Number = proto.Int32(9)
			},
		},
		{
			name: "DmarcResult.result dropped",
			want: "DmarcResult.result is written and not declared",
			mutate: func(fileProtos testFileProtos) {
				dropField(testPlantedMessage(t, fileProtos, "protocol/mail.proto", "DmarcResult"), "result")
			},
		},
		{
			name: "a field added to a row in a file the old walk never read",
			want: "MemberRow.note is declared and not written",
			mutate: func(fileProtos testFileProtos) {
				message := testPlantedMessage(t, fileProtos, "protocol/bridge/auth.proto", "MemberRow")
				message.Field = append(message.Field, testNewField("note", 5, descriptorpb.FieldDescriptorProto_TYPE_STRING))
			},
		},
		{
			name: "a value added to GkmHintKind",
			want: "GkmHintKind.GKM_HINT_STRAY is declared and not written",
			mutate: func(fileProtos testFileProtos) {
				for _, enum := range fileProtos[gkm].EnumType {
					if enum.GetName() == "GkmHintKind" {
						enum.Value = append(enum.Value, &descriptorpb.EnumValueDescriptorProto{
							Name:   proto.String("GKM_HINT_STRAY"),
							Number: proto.Int32(6),
						})
					}
				}
			},
		},
		{
			name: "EvsDropPath.map_parts unpacked, which changes that field's encoding",
			want: "EvsDropPath.map_parts sets options",
			mutate: func(fileProtos testFileProtos) {
				field := testPlantedField(t, testPlantedMessage(t, fileProtos, evs, "EvsDropPath"), "map_parts")
				field.Options = &descriptorpb.FieldOptions{Packed: proto.Bool(false)}
			},
		},
		{
			name: "RecordHeader.tainted made optional",
			want: "RecordHeader.tainted is optional",
			mutate: func(fileProtos testFileProtos) {
				optional(testPlantedMessage(t, fileProtos, "protocol/record.proto", "RecordHeader"), "tainted")
			},
		},
		{
			name: "DirectoryCard.seq made optional",
			want: "DirectoryCard.seq is optional",
			mutate: func(fileProtos testFileProtos) {
				optional(testPlantedMessage(t, fileProtos, "protocol/directory.proto", "DirectoryCard"), "seq")
			},
		},
		{
			name: "a message nested in SocketTicket",
			want: "SocketTicket nests message Stray",
			mutate: func(fileProtos testFileProtos) {
				message := testPlantedMessage(t, fileProtos, "protocol/socket.proto", "SocketTicket")
				message.NestedType = []*descriptorpb.DescriptorProto{{Name: proto.String("Stray")}}
			},
		},
		{
			name: "an enum nested in EvsPlace",
			want: "EvsPlace nests enum Stray",
			mutate: func(fileProtos testFileProtos) {
				testPlantedMessage(t, fileProtos, evs, "EvsPlace").EnumType = []*descriptorpb.EnumDescriptorProto{nestedEnum}
			},
		},
		{
			name: "fenced LeafWrap moved out of gkm.proto",
			want: "LeafWrap is in protocol/evs.proto, and its fence puts it in protocol/gkm.proto",
			mutate: func(fileProtos testFileProtos) {
				gkmFile, evsFile := fileProtos[gkm], fileProtos[evs]
				evsFile.MessageType = append(evsFile.MessageType, testPlantedMessage(t, fileProtos, gkm, "LeafWrap"))
				gkmFile.MessageType = slices.DeleteFunc(gkmFile.MessageType, func(message *descriptorpb.DescriptorProto) bool {
					return message.GetName() == "LeafWrap"
				})
				gkmFile.Dependency = append(gkmFile.Dependency, evs)
			},
		},
		{
			name: "a stray message in a file the old walk never read",
			want: "protocol/push.proto declares message Stray",
			mutate: func(fileProtos testFileProtos) {
				file := fileProtos["protocol/push.proto"]
				file.MessageType = append(file.MessageType, &descriptorpb.DescriptorProto{Name: proto.String("Stray")})
			},
		},
		{
			name: "a stray enum in a file the old walk never read",
			want: "protocol/types.proto declares enum Stray",
			mutate: func(fileProtos testFileProtos) {
				file := fileProtos["protocol/types.proto"]
				file.EnumType = append(file.EnumType, nestedEnum)
			},
		},
		{
			name: "a service",
			want: "protocol/stream.proto declares service Stray",
			mutate: func(fileProtos testFileProtos) {
				fileProtos["protocol/stream.proto"].Service = []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Stray")}}
			},
		},
		{
			name: "a file option",
			want: "protocol/tls.proto sets options",
			mutate: func(fileProtos testFileProtos) {
				fileProtos["protocol/tls.proto"].Options.JavaPackage = proto.String("stray")
			},
		},
		{
			name: "a message option",
			want: "SmtpProof sets options",
			mutate: func(fileProtos testFileProtos) {
				message := testPlantedMessage(t, fileProtos, "protocol/smtp.proto", "SmtpProof")
				message.Options = &descriptorpb.MessageOptions{Deprecated: proto.Bool(true)}
			},
		},
		{
			name: "an enum value option",
			want: "EvsPushFlag.EVS_PUSH_FORCE sets options",
			mutate: func(fileProtos testFileProtos) {
				for _, enum := range fileProtos[evs].EnumType {
					if enum.GetName() == "EvsPushFlag" {
						enum.Value[1].Options = &descriptorpb.EnumValueOptions{Deprecated: proto.Bool(true)}
					}
				}
			},
		},
	}
	fences := testReadFences(t)
	// The rebuild alone must differ in nothing, or every case below would pass for the wrong reason.
	control := testPlantedFiles(t, func(testFileProtos) {})
	if differences := testWireDifferences(fences, control); len(differences) != 0 {
		t.Fatalf("the unplanted copy differs: %v", differences)
	}
	for _, c := range cases {
		differences := testWireDifferences(fences, testPlantedFiles(t, c.mutate))
		if !testHasDifference(differences, c.want) {
			t.Errorf("%s: wanted %q, found %v", c.name, c.want, differences)
		}
	}
}

// The field lists the design writes for what it fences nowhere (§10.5, §10.14, §11.10), which a descriptor must keep
// name for name, its numbers following the order written. testUnfencedFence holds their types.
func TestWrittenFieldListsMatchTheirMessages(t *testing.T) {
	design := testReadDesign(t)
	cases := []struct {
		name   string
		list   string
		fields []string
	}{
		{
			name:   "ReaderKey",
			list:   "purpose reader-key, {sidecar_id, xwing_public_key, not_after}",
			fields: []string{"sidecar_id", "xwing_public_key", "not_after"},
		},
		{
			name:   "GkmHint",
			list:   "GkmHint{group_id, epoch, kind, recipient}",
			fields: []string{"group_id", "epoch", "kind", "recipient"},
		},
		{
			name:   "EvsHeadChanged",
			list:   "EvsHeadChanged{ref_id, version, chain, push_id}",
			fields: []string{"ref_id", "version", "chain", "push_id"},
		},
	}
	for _, c := range cases {
		if !strings.Contains(string(design), c.list) {
			t.Errorf("the design no longer writes %q", c.list)
		}
		fields := testMessage(t, c.name).Fields()
		if fields.Len() != len(c.fields) {
			t.Errorf("%s has %d fields, and the design lists %d", c.name, fields.Len(), len(c.fields))
			continue
		}
		for i, want := range c.fields {
			if field := fields.ByNumber(protoreflect.FieldNumber(i + 1)); field == nil || string(field.Name()) != want {
				t.Errorf("%s's field %d should be %s, the order the design writes", c.name, i+1, want)
			}
		}
	}
}
