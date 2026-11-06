// Every fenced proto block in DESIGN.md, read against what this package registers, so a field number, type or
// reservation that leaves the design fails here. A fence and its descriptor must agree exactly, in both
// directions. Whatever a file declares beyond the fences has to be named in testUnfencedDeclarations, with why,
// which is where a reviewer reads what this repository added to the design's wire.

package protocol

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const testDesignPath = "../DESIGN.md"

// Written so a fence's string, identifier, number and punctuation each stay one token.
var testFenceToken = regexp.MustCompile(`"[^"]*"|[A-Za-z_][A-Za-z0-9_.]*|0x[0-9A-Fa-f]+|[0-9]+|[{};=,<>]`)

type testFenceField struct {
	name     string
	number   int32
	typeName string
	repeated bool
}

type testFenceMessage struct {
	fields          []testFenceField
	reservedNumbers []int32
	reservedNames   []string
}

type testFenceEnum struct {
	values          map[string]int32
	reservedNumbers []int32
	reservedNames   []string
}

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

// Every fenced proto block in DESIGN.md, read into one set of declarations.
func testReadFences(t *testing.T) *testFences {
	design, err := os.ReadFile(testDesignPath)
	if err != nil {
		t.Fatalf("this test needs the design beside the module: %v", err)
	}
	fences := &testFences{messages: map[string]*testFenceMessage{}, enums: map[string]*testFenceEnum{}}
	// One fence's messages and enums. Fences hold no nesting, oneof or option inside a body, so anything else
	// stops the test rather than being skipped.
	parseFence := func(fence string) {
		var source strings.Builder
		for line := range strings.SplitSeq(fence, "\n") {
			code, _, _ := strings.Cut(line, "//")
			source.WriteString(code + "\n")
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
					t.Errorf("the design declares message %s twice", name)
				}
				message := &testFenceMessage{}
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
					t.Errorf("the design declares enum %s twice", name)
				}
				enum := &testFenceEnum{values: map[string]int32{}}
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
	var fence *strings.Builder
	count := 0
	for line := range strings.SplitSeq(string(design), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case fence == nil && trimmed == "```proto":
			fence = &strings.Builder{}
		case fence != nil && trimmed == "```":
			parseFence(fence.String())
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

// A declaration in this package, or nil, for a test that reports what is missing rather than stopping at it.
func testLookup(name string) protoreflect.Descriptor {
	descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(testProtoPackage + "." + name))
	if err != nil {
		return nil
	}
	return descriptor
}

// §4.9, and the rule that numbers stay as written: every field of every fenced message, in number, name, type and
// cardinality, with nothing added or missing, and every reserved number.
func TestFencedMessagesMatchTheirDescriptors(t *testing.T) {
	typeName := func(field protoreflect.FieldDescriptor) string {
		if field.IsMap() {
			return "map<" + field.MapKey().Kind().String() + "," + field.MapValue().Kind().String() + ">"
		}
		switch field.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			return string(field.Message().Name())
		case protoreflect.EnumKind:
			return string(field.Enum().Name())
		}
		return field.Kind().String()
	}
	fences := testReadFences(t)
	for name, fence := range fences.messages {
		message, ok := testLookup(name).(protoreflect.MessageDescriptor)
		if !ok {
			t.Errorf("%s is in the design and no message here", name)
			continue
		}
		fields := message.Fields()
		if fields.Len() != len(fence.fields) {
			t.Errorf("%s has %d fields, and the design %d", name, fields.Len(), len(fence.fields))
		}
		for _, want := range fence.fields {
			field := fields.ByName(protoreflect.Name(want.name))
			if field == nil {
				t.Errorf("%s.%s is in the design and not here", name, want.name)
				continue
			}
			if int32(field.Number()) != want.number {
				t.Errorf("%s.%s is %d, and the design writes %d", name, want.name, field.Number(), want.number)
			}
			if got := typeName(field); got != want.typeName {
				t.Errorf("%s.%s is %s, and the design writes %s", name, want.name, got, want.typeName)
			}
			if repeated := field.IsList(); repeated != want.repeated {
				t.Errorf("%s.%s repeated is %t, and the design writes %t", name, want.name, repeated, want.repeated)
			}
		}
		got := testSorted(testReservedNumbers(message.ReservedRanges()))
		if !slices.Equal(got, testSorted(fence.reservedNumbers)) {
			t.Errorf("%s reserves %v, and the design %v", name, got, fence.reservedNumbers)
		}
		if message.ReservedNames().Len() != len(fence.reservedNames) {
			t.Errorf("%s reserves %d names, and the design %d", name, message.ReservedNames().Len(), len(fence.reservedNames))
		}
		for _, reservedName := range fence.reservedNames {
			if !message.ReservedNames().Has(protoreflect.Name(reservedName)) {
				t.Errorf("%s does not reserve %s", name, reservedName)
			}
		}
	}
}

// Enum values and reservations, exactly. SignedType's fence is its zero value and a comment, because owners add
// values with their formats (§6.11), so there the fence need only be contained.
func TestFencedEnumsMatchTheirDescriptors(t *testing.T) {
	fences := testReadFences(t)
	for name, fence := range fences.enums {
		enum, ok := testLookup(name).(protoreflect.EnumDescriptor)
		if !ok {
			t.Errorf("%s is in the design and no enum here", name)
			continue
		}
		values := enum.Values()
		if name != "SignedType" && values.Len() != len(fence.values) {
			t.Errorf("%s has %d values, and the design %d", name, values.Len(), len(fence.values))
		}
		for valueName, number := range fence.values {
			value := values.ByName(protoreflect.Name(valueName))
			if value == nil {
				t.Errorf("%s.%s is in the design and not here", name, valueName)
				continue
			}
			if int32(value.Number()) != number {
				t.Errorf("%s.%s is %d, and the design writes %d", name, valueName, value.Number(), number)
			}
		}
		got := testSorted(testEnumReservedNumbers(enum.ReservedRanges()))
		if !slices.Equal(got, testSorted(fence.reservedNumbers)) {
			t.Errorf("%s reserves %v, and the design %v", name, got, fence.reservedNumbers)
		}
		if enum.ReservedNames().Len() != len(fence.reservedNames) {
			t.Errorf("%s reserves %d names, and the design %d", name, enum.ReservedNames().Len(), len(fence.reservedNames))
		}
		for _, reservedName := range fence.reservedNames {
			if !enum.ReservedNames().Has(protoreflect.Name(reservedName)) {
				t.Errorf("%s does not reserve %s", name, reservedName)
			}
		}
	}
}

// What the service files declare that no fence does, with where the design writes it. A new declaration joins this
// list deliberately, so the design's wire and this one cannot quietly part.
var testUnfencedDeclarations = map[string]string{
	"protocol/gkm.proto:ReaderKey":   "§10.5's field list",
	"protocol/gkm.proto:GroupForm":   "§2.8's gkm-1",
	"protocol/gkm.proto:GkmHint":     "§10.14's field list",
	"protocol/gkm.proto:GkmHintKind": "§10.14's kinds",

	"protocol/evs.proto:EvsHeadChanged": "§11.10's field list",
	"protocol/evs.proto:EvsPushFlag":    "EvsPush.flags' comment, numbers as written",
	"protocol/evs.proto:EvsLocatorKind": "EvsLocator.kind's comment, numbers as written",
	"protocol/evs.proto:EvsVersioning":  "EvsEntryVersion.versioning's comment, numbers as written",
	"protocol/evs.proto:EvsWindowFlag":  "§11.8's entry row, bits as written",

	"protocol/smtp.proto:SmtpPreambleCode": "§6.11's edge codes, numbers as written",
	"protocol/smtp.proto:SmtpProofCode":    "§6.11's edge codes, numbers as written",

	"protocol/mail.proto:SpfResult":    "MailAuthEvidence.spf's comment",
	"protocol/mail.proto:SpfVerdict":   "MailAuthEvidence.spf's comment",
	"protocol/mail.proto:DkimResult":   "MailAuthEvidence.dkim's comment",
	"protocol/mail.proto:DkimVerdict":  "MailAuthEvidence.dkim's comment",
	"protocol/mail.proto:DmarcResult":  "MailAuthEvidence.dmarc's comment",
	"protocol/mail.proto:DmarcVerdict": "MailAuthEvidence.dmarc's comment",
	"protocol/mail.proto:ArcResult":    "MailAuthEvidence.arc's comment",
	"protocol/mail.proto:ArcSet":       "MailAuthEvidence.arc's comment",
	"protocol/mail.proto:ArcVerdict":   "MailAuthEvidence.arc's comment",
}

// The reverse direction: a service file declares what its fences do, and what testUnfencedDeclarations names.
func TestServiceFilesDeclareNothingUnaccountedFor(t *testing.T) {
	fences := testReadFences(t)
	declared := map[string]bool{}
	for _, path := range []string{
		"protocol/directory.proto", "protocol/evs.proto", "protocol/evsindex.proto", "protocol/gkm.proto",
		"protocol/mail.proto", "protocol/record.proto", "protocol/search.proto", "protocol/smtp.proto",
		"protocol/socket.proto", "protocol/tls.proto",
	} {
		file := testFile(t, path)
		names := []string{}
		for i := range file.Messages().Len() {
			names = append(names, string(file.Messages().Get(i).Name()))
		}
		for i := range file.Enums().Len() {
			names = append(names, string(file.Enums().Get(i).Name()))
		}
		for _, name := range names {
			key := path + ":" + name
			declared[key] = true
			_, unfenced := testUnfencedDeclarations[key]
			fenced := fences.messages[name] != nil || fences.enums[name] != nil
			if fenced == unfenced {
				t.Errorf("%s: fenced is %t, and listed as unfenced is %t", key, fenced, unfenced)
			}
		}
	}
	for _, key := range slices.Sorted(maps.Keys(testUnfencedDeclarations)) {
		if !declared[key] {
			t.Errorf("%s is listed and not declared", key)
		}
	}
}
