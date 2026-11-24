// Every fenced proto block in DESIGN.md, RECORD.md and DESIGN-COMPUTE.md, and what the design writes any other way, read
// against what this package registers, so a wire that leaves the design fails here. testWireDifferences says exactly what is held. Whatever the
// package declares beyond the fences is written out in testUnfencedFence, with where the design writes it, which is
// where a reviewer reads what this repository added to the design's wire, and a field an owner's answer adds to a
// fenced message before design-records folds it in is in testFenceAdditions, with the question that holds the answer,
// as one it takes out, its number reserved, is in testFenceReservations, and an enum value it takes out in
// testFenceValueReservations.
//
// DESIGN-COMPUTE.md's fences (CARCH-M11-04) name no file as DESIGN.md's do, and the plan moved some of their messages
// (CONTRACTS C-36), so testComputeFencePlacements places each declaration; three extend a declaration DESIGN.md or
// RECORD.md writes, adding fields or values to it. Their wire lands with each compute area's task, so what they write
// and no file declares yet, a whole message or enum or an extension's field or value, is reported as unbuilt rather
// than as a mismatch; a compute message a file declares is compared whole, as any.

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

// Where RECORD.md is from this directory, which writes record.proto's entry bodies as its own fences (§16.8's kinds
// row). It sits beside the module, and the second path serves a tree that moves it as DESIGN.md moves.
var testRecordMdPaths = []string{"../RECORD.md", "../../RECORD.md"}

// Where DESIGN-COMPUTE.md is from this directory, which writes compute's wire as fences of its own. It sits beside
// DESIGN.md, and the second path serves a release branch, as testDesignPaths' does.
var testComputeDesignPaths = []string{"../DESIGN-COMPUTE.md", "../../DESIGN-COMPUTE.md"}

// Where a DESIGN-COMPUTE.md fence's declaration goes: the file the plan places it in, since the fences name none in
// the form DESIGN.md's do, and whether the fence extends a declaration another document writes, adding to it.
type testComputeFencePlacement struct {
	path    string
	extends bool
}

// Every declaration DESIGN-COMPUTE.md's fences write, with where it goes. Each fence's own words name its file where it
// names one (attest.proto, record.proto); the design's compute.proto header and search messages go where CONTRACTS C-36
// moved them, infer.proto and websearch.proto, so BAL's compute.proto declares neither. A declaration a fence writes
// that is not here stops the test, so a new fence is placed when it is written.
var testComputeFencePlacements = map[string]testComputeFencePlacement{
	// §5.8, ATTEST-M11-01
	"AttestationResult": {path: "protocol/attest.proto"},
	// §6.6's header, INFER's (C-36)
	"ComputeInferHeader": {path: "protocol/infer.proto"},
	// §6.8's fields 11-15 on RECORD.md section 12's body: INFER-M11-07's 11-14, CTXH-M11-01's 15 (C-26)
	"ModelCallBody": {path: "protocol/record.proto", extends: true},
	// §21.5's payment, SRCH-M13-01's (C-36)
	"ComputeSearchAuthorizeRequest": {path: "protocol/websearch.proto"},
	"SearchPayee":                   {path: "protocol/websearch.proto"},
	"SearchOutcomes":                {path: "protocol/websearch.proto"},
	"ComputeSearchAuthorization":    {path: "protocol/websearch.proto"},
	// §24.4's session entries and ModelCallBody's context, CTXH-M11-01's (C-26)
	"SessionEntryBody": {path: "protocol/record.proto"},
	"SessionPart":      {path: "protocol/record.proto"},
	"SessionBlobBody":  {path: "protocol/record.proto"},
	"CallContext":      {path: "protocol/record.proto"},
	// §27.9's version 3 of DESIGN §16.8's ApprovalDecision and channel 4, and the auto_verdict entry, SAFE's (C-26)
	"ApprovalDecision": {path: "protocol/record.proto", extends: true},
	"AutoVerdict":      {path: "protocol/record.proto"},
	"ApprovalChannel":  {path: "protocol/record.proto", extends: true},
	"AutoVerdictBody":  {path: "protocol/record.proto"},
	"AutoInput":        {path: "protocol/record.proto"},
}

// A fence's block comments, which DESIGN-COMPUTE.md's use (ApprovalChannel's /* DESIGN's 0-3 */) and DESIGN.md's do not.
var testFenceBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

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
	// RECORD.md's fences after its first name no file, and each is record.proto's.
	"RecordDepositBatch": "protocol/record.proto",
	"LedgerScopeBody":    "protocol/record.proto",
	"LogSettingsBody":    "protocol/record.proto",
	"DisclosurePacket":   "protocol/record.proto",
	"AttestationBody":    "protocol/record.proto",
	"ModelManifest":      "protocol/record.proto",
	"RunCostBody":        "protocol/record.proto",
}

// A field as a fence writes it. A map's typeName reads map<key,value>.
type testFenceField struct {
	name     string
	number   int32
	typeName string
	repeated bool
	// a DESIGN-COMPUTE.md fence adds it to a message another document writes, so it is unbuilt until declared
	extension bool
}

// A message as a fence writes it, with the file that fence places it in.
type testFenceMessage struct {
	path            string
	fields          []testFenceField
	reservedNumbers []int32
	reservedNames   []string
	// only DESIGN-COMPUTE.md's fences write it, so it is unbuilt until a file declares it
	compute bool
}

// An enum as a fence writes it, with the file that fence places it in.
type testFenceEnum struct {
	path            string
	values          map[string]int32
	reservedNumbers []int32
	reservedNames   []string
	// only DESIGN-COMPUTE.md's fences write it, so it is unbuilt until a file declares it
	compute bool
	// the values a DESIGN-COMPUTE.md fence adds to an enum another document writes, each unbuilt until declared
	extensionValues map[string]bool
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
	testParseFenceSource(t, fences, source.String(), func(name string) string {
		if declarationPaths[name] != "" {
			return declarationPaths[name]
		}
		return firstPath
	})
}

// One DESIGN-COMPUTE.md fence's messages and enums, read into fences, each in the file testComputeFencePlacements gives
// it. Its comments, block comments among them, are no part of its wire.
func testParseComputeFence(t *testing.T, fences *testFences, fence string) {
	var source strings.Builder
	for line := range strings.SplitSeq(testFenceBlockComment.ReplaceAllString(fence, " "), "\n") {
		code, _, _ := strings.Cut(line, "//")
		source.WriteString(code + "\n")
	}
	testParseFenceSource(t, fences, source.String(), func(name string) string {
		placement, ok := testComputeFencePlacements[name]
		if !ok {
			t.Fatalf("a DESIGN-COMPUTE.md fence writes %s, and testComputeFencePlacements does not place it", name)
		}
		return placement.path
	})
}

// A fence's code, its comments gone, read into fences, each declaration in the file pathOf gives it.
func testParseFenceSource(t *testing.T, fences *testFences, source string, pathOf func(name string) string) {
	tokens := testFenceToken.FindAllString(source, -1)
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

// DESIGN-COMPUTE.md's bytes, from the first of testComputeDesignPaths that holds it.
func testReadComputeDesign(t testing.TB) []byte {
	design, err := os.ReadFile(testComputeDesignPaths[0])
	if errors.Is(err, os.ErrNotExist) {
		design, err = os.ReadFile(testComputeDesignPaths[1])
	}
	if err != nil {
		t.Fatalf("this test needs DESIGN-COMPUTE.md beside the module: %v", err)
	}
	return design
}

// RECORD.md's bytes, from the first of testRecordMdPaths that holds it.
func testReadRecordMd(t testing.TB) []byte {
	recordMd, err := os.ReadFile(testRecordMdPaths[0])
	if errors.Is(err, os.ErrNotExist) {
		recordMd, err = os.ReadFile(testRecordMdPaths[1])
	}
	if err != nil {
		t.Fatalf("this test needs RECORD.md beside the module: %v", err)
	}
	return recordMd
}

// Each fenced proto block in a document, read into fences, and how many there were.
func testParseFences(t *testing.T, fences *testFences, document []byte) int {
	return testParseFencesWith(t, fences, document, testParseFence)
}

// testParseFences with parse reading each fence.
func testParseFencesWith(t *testing.T, fences *testFences, document []byte, parse func(t *testing.T, fences *testFences, fence string)) int {
	var fence *strings.Builder
	count := 0
	for line := range strings.SplitSeq(string(document), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case fence == nil && trimmed == "```proto":
			fence = &strings.Builder{}
		case fence != nil && trimmed == "```":
			parse(t, fences, fence.String())
			fence = nil
			count++
		case fence != nil:
			fence.WriteString(line + "\n")
		}
	}
	return count
}

// Every fenced proto block in DESIGN.md and RECORD.md, then testUnfencedFence, read into one set of declarations,
// with testFenceAdditions' fields and testFenceValueAdditions' values joining the fences they extend and
// testFenceReservations' fields and testFenceValueReservations' values leaving theirs. A declaration that later gains a fence is then written twice, which
// says to take it out of testUnfencedFence, and an added field or value the design comes to write, or a reserved one
// it comes to reserve, fails until its line leaves its list.
func testReadFences(t *testing.T) *testFences {
	fences := &testFences{messages: map[string]*testFenceMessage{}, enums: map[string]*testFenceEnum{}}
	count := testParseFences(t, fences, testReadDesign(t))
	// A parser that found nothing would pass everything below.
	if count < 27 || len(fences.messages) < 120 {
		t.Fatalf("found %d fences and %d messages, too few to have read the design", count, len(fences.messages))
	}
	designMessageCount := len(fences.messages)
	recordMdCount := testParseFences(t, fences, testReadRecordMd(t))
	if recordMdCount < 8 || len(fences.messages)-designMessageCount < 40 {
		t.Fatalf("found %d fences and %d messages in RECORD.md, too few to have read it", recordMdCount, len(fences.messages)-designMessageCount)
	}
	computeFences := &testFences{messages: map[string]*testFenceMessage{}, enums: map[string]*testFenceEnum{}}
	computeCount := testParseFencesWith(t, computeFences, testReadComputeDesign(t), testParseComputeFence)
	if computeCount < 7 || len(computeFences.messages) < 15 {
		t.Fatalf("found %d fences and %d messages in DESIGN-COMPUTE.md, too few to have read it", computeCount, len(computeFences.messages))
	}
	for _, finding := range testJoinComputeFences(fences, computeFences, testComputeFencePlacements) {
		t.Error(finding)
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
	for _, finding := range testApplyValueAdditions(fences, testFenceValueAdditions) {
		t.Error(finding)
	}
	for _, finding := range testApplyReservations(fences, testFenceReservations) {
		t.Error(finding)
	}
	for _, finding := range testApplyValueReservations(fences, testFenceValueReservations) {
		t.Error(finding)
	}
	return fences
}

// Joins compute's declarations to fences. One only DESIGN-COMPUTE.md writes joins whole, marked compute; one its
// placement marks as extending adds its fields, values and reservations to the fence that writes the rest, each field
// and value marked an extension. Answers what cannot join: a declaration another document writes that is not marked as
// extended, an extension of what no other fence writes, one placed in another file than its base, and a field or value
// the base already writes or reserves, by name or number.
func testJoinComputeFences(fences *testFences, compute *testFences, placements map[string]testComputeFencePlacement) []string {
	findings := []string{}
	for _, name := range slices.Sorted(maps.Keys(compute.messages)) {
		message := compute.messages[name]
		base := fences.messages[name]
		switch {
		case base == nil && placements[name].extends:
			findings = append(findings, fmt.Sprintf("DESIGN-COMPUTE.md extends message %s, which no other fence writes", name))
		case base == nil:
			message.compute = true
			fences.messages[name] = message
		case !placements[name].extends:
			findings = append(findings, fmt.Sprintf("message %s is written twice: by DESIGN-COMPUTE.md, and by DESIGN.md or RECORD.md", name))
		case base.path != message.path:
			findings = append(findings, fmt.Sprintf("DESIGN-COMPUTE.md extends %s in %s, and its fence puts it in %s", name, message.path, base.path))
		default:
			for _, field := range message.fields {
				taken := slices.ContainsFunc(base.fields, func(written testFenceField) bool {
					return written.name == field.name || written.number == field.number
				})
				if taken || slices.Contains(base.reservedNumbers, field.number) {
					findings = append(findings, fmt.Sprintf("DESIGN-COMPUTE.md adds %s.%s at %d, which its fence already writes or reserves", name, field.name, field.number))
					continue
				}
				field.extension = true
				base.fields = append(base.fields, field)
			}
			base.reservedNumbers = append(base.reservedNumbers, message.reservedNumbers...)
			base.reservedNames = append(base.reservedNames, message.reservedNames...)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(compute.enums)) {
		enum := compute.enums[name]
		base := fences.enums[name]
		switch {
		case base == nil && placements[name].extends:
			findings = append(findings, fmt.Sprintf("DESIGN-COMPUTE.md extends enum %s, which no other fence writes", name))
		case base == nil:
			enum.compute = true
			fences.enums[name] = enum
		case !placements[name].extends:
			findings = append(findings, fmt.Sprintf("enum %s is written twice: by DESIGN-COMPUTE.md, and by DESIGN.md or RECORD.md", name))
		case base.path != enum.path:
			findings = append(findings, fmt.Sprintf("DESIGN-COMPUTE.md extends %s in %s, and its fence puts it in %s", name, enum.path, base.path))
		default:
			if base.extensionValues == nil {
				base.extensionValues = map[string]bool{}
			}
			for _, valueName := range slices.Sorted(maps.Keys(enum.values)) {
				number := enum.values[valueName]
				_, taken := base.values[valueName]
				for _, written := range base.values {
					taken = taken || written == number
				}
				if taken || slices.Contains(base.reservedNumbers, number) {
					findings = append(findings, fmt.Sprintf("DESIGN-COMPUTE.md adds %s.%s at %d, which its fence already writes or reserves", name, valueName, number))
					continue
				}
				base.values[valueName] = number
				base.extensionValues[valueName] = true
			}
			base.reservedNumbers = append(base.reservedNumbers, enum.reservedNumbers...)
			base.reservedNames = append(base.reservedNames, enum.reservedNames...)
		}
	}
	return findings
}

// Takes each field out of the fence that writes it and reserves its number there, and says which cannot leave: a
// message no fence writes, a field its fence no longer writes at that number, or a number the design now reserves
// itself, whose line should leave the list.
func testApplyReservations(fences *testFences, reservations []testFenceReservation) []string {
	findings := []string{}
	for _, reservation := range reservations {
		message := fences.messages[reservation.message]
		if message == nil {
			findings = append(findings, fmt.Sprintf("%s loses %s by %s, and no fence writes that message", reservation.message, reservation.name, reservation.question))
			continue
		}
		index := slices.IndexFunc(message.fields, func(field testFenceField) bool {
			return field.name == reservation.name && field.number == reservation.number
		})
		if index < 0 || slices.Contains(message.reservedNumbers, reservation.number) {
			findings = append(findings, fmt.Sprintf("the design no longer writes %s.%s at %d, or reserves it: drop its line from testFenceReservations (%s)", reservation.message, reservation.name, reservation.number, reservation.question))
			continue
		}
		message.fields = slices.Delete(message.fields, index, index+1)
		message.reservedNumbers = append(message.reservedNumbers, reservation.number)
	}
	return findings
}

// The reservation list's own checks, on fences planted for it: a written field leaves and its number is reserved, and
// a field the fence does not write, a number it already reserves, or a message no fence writes is a finding.
func TestFenceReservationsTakeOnlyWhatTheDesignWrites(t *testing.T) {
	planted := func() *testFences {
		return &testFences{enums: map[string]*testFenceEnum{}, messages: map[string]*testFenceMessage{
			"Planted": {
				path:            "protocol/types.proto",
				fields:          []testFenceField{{name: "kept", number: 1, typeName: "uint32"}, {name: "leaving", number: 2, typeName: "uint32"}},
				reservedNumbers: []int32{9},
			},
		}}
	}
	fences := planted()
	findings := testApplyReservations(fences, []testFenceReservation{{message: "Planted", name: "leaving", number: 2, question: "q"}})
	message := fences.messages["Planted"]
	if len(findings) != 0 || len(message.fields) != 1 || message.fields[0].name != "kept" || !slices.Equal(message.reservedNumbers, []int32{9, 2}) {
		t.Errorf("a written field: %v, %+v", findings, message)
	}
	for _, reservation := range []testFenceReservation{
		{message: "Planted", name: "unwritten", number: 3, question: "q"},
		{message: "Planted", name: "leaving", number: 4, question: "q"},
		{message: "Planted", name: "kept", number: 9, question: "q"},
		{message: "Unwritten", name: "leaving", number: 2, question: "q"},
	} {
		if findings := testApplyReservations(planted(), []testFenceReservation{reservation}); len(findings) != 1 {
			t.Errorf("%s.%s at %d: %v", reservation.message, reservation.name, reservation.number, findings)
		}
	}
}

// Takes each value out of the enum fence that writes it and reserves its number there, and says which cannot leave:
// an enum no fence writes, a value its fence no longer writes at that number, or a number the design now reserves
// itself, whose line should leave the list.
func testApplyValueReservations(fences *testFences, reservations []testFenceValueReservation) []string {
	findings := []string{}
	for _, reservation := range reservations {
		enum := fences.enums[reservation.enum]
		if enum == nil {
			findings = append(findings, fmt.Sprintf("%s loses %s by %s, and no fence writes that enum", reservation.enum, reservation.name, reservation.question))
			continue
		}
		number, written := enum.values[reservation.name]
		if !written || number != reservation.number || slices.Contains(enum.reservedNumbers, reservation.number) {
			findings = append(findings, fmt.Sprintf("the design no longer writes %s.%s at %d, or reserves it: drop its line from testFenceValueReservations (%s)", reservation.enum, reservation.name, reservation.number, reservation.question))
			continue
		}
		delete(enum.values, reservation.name)
		enum.reservedNumbers = append(enum.reservedNumbers, reservation.number)
	}
	return findings
}

// The value reservation list's own checks, on fences planted for it: a written value leaves and its number is
// reserved, and a value the fence does not write, one it writes at another number, a number it already reserves, or an
// enum no fence writes is a finding.
func TestFenceValueReservationsTakeOnlyWhatTheDesignWrites(t *testing.T) {
	planted := func() *testFences {
		return &testFences{messages: map[string]*testFenceMessage{}, enums: map[string]*testFenceEnum{
			"Planted": {path: "protocol/types.proto", values: map[string]int32{"PLANTED_NONE": 0, "PLANTED_KEPT": 1, "PLANTED_LEAVING": 2}, reservedNumbers: []int32{9}},
		}}
	}
	fences := planted()
	findings := testApplyValueReservations(fences, []testFenceValueReservation{{enum: "Planted", name: "PLANTED_LEAVING", number: 2, question: "q"}})
	enum := fences.enums["Planted"]
	if _, written := enum.values["PLANTED_LEAVING"]; len(findings) != 0 || written || len(enum.values) != 2 || !slices.Equal(enum.reservedNumbers, []int32{9, 2}) {
		t.Errorf("a written value: %v, %+v", findings, enum)
	}
	for _, reservation := range []testFenceValueReservation{
		{enum: "Planted", name: "PLANTED_UNWRITTEN", number: 3, question: "q"},
		{enum: "Planted", name: "PLANTED_LEAVING", number: 4, question: "q"},
		{enum: "Planted", name: "PLANTED_KEPT", number: 9, question: "q"},
		{enum: "Unwritten", name: "UNWRITTEN_LEAVING", number: 2, question: "q"},
	} {
		if findings := testApplyValueReservations(planted(), []testFenceValueReservation{reservation}); len(findings) != 1 {
			t.Errorf("%s.%s at %d: %v", reservation.enum, reservation.name, reservation.number, findings)
		}
	}
}

// Joins each value to the enum it extends, and says which cannot join: an enum no fence writes, or a
// value or number the design now writes itself, whose line should leave the list.
func testApplyValueAdditions(fences *testFences, additions []testFenceValueAddition) []string {
	findings := []string{}
	for _, addition := range additions {
		enum := fences.enums[addition.enum]
		if enum == nil {
			findings = append(findings, fmt.Sprintf("%s gains %s by %s, and no fence writes that enum", addition.enum, addition.name, addition.question))
			continue
		}
		_, written := enum.values[addition.name]
		for _, number := range enum.values {
			written = written || number == addition.number
		}
		if written || slices.Contains(enum.reservedNumbers, addition.number) {
			findings = append(findings, fmt.Sprintf("the design now writes %s.%s or its number %#x: drop its line from testFenceValueAdditions (%s)", addition.enum, addition.name, addition.number, addition.question))
			continue
		}
		enum.values[addition.name] = addition.number
	}
	return findings
}

// The value list's own checks, on fences planted for it: a value joins, and a value or number already
// written, or an enum no fence writes, is a finding rather than a second copy.
func TestFenceValueAdditionsJoinOnlyWhatTheDesignLeavesOut(t *testing.T) {
	planted := func() *testFences {
		return &testFences{messages: map[string]*testFenceMessage{}, enums: map[string]*testFenceEnum{
			"Planted": {path: "protocol/types.proto", values: map[string]int32{"PLANTED_NONE": 0, "PLANTED_ONE": 1}, reservedNumbers: []int32{9}},
		}}
	}
	fences := planted()
	if findings := testApplyValueAdditions(fences, []testFenceValueAddition{{enum: "Planted", name: "PLANTED_TWO", number: 2, question: "q"}}); len(findings) != 0 || fences.enums["Planted"].values["PLANTED_TWO"] != 2 {
		t.Errorf("a new value: %v", findings)
	}
	for _, addition := range []testFenceValueAddition{
		{enum: "Planted", name: "PLANTED_ONE", number: 3, question: "q"},
		{enum: "Planted", name: "PLANTED_THREE", number: 1, question: "q"},
		{enum: "Planted", name: "PLANTED_NINE", number: 9, question: "q"},
		{enum: "Unwritten", name: "UNWRITTEN_ONE", number: 1, question: "q"},
	} {
		if findings := testApplyValueAdditions(planted(), []testFenceValueAddition{addition}); len(findings) != 1 {
			t.Errorf("%s.%s: %v", addition.enum, addition.name, findings)
		}
	}
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
	differences, _ := testWireReport(fences, files)
	return differences
}

// testWireDifferences, with what DESIGN-COMPUTE.md writes and no file declares yet apart: a message or enum only its
// fences write, and a field or value they add to another document's, each unbuilt until the task that adds it lands.
// A compute message a file declares is compared whole, as any, and so is the rest of an extended one.
func testWireReport(fences *testFences, files *protoregistry.Files) (differences []string, unbuilt []string) {
	differences = []string{}
	unbuilt = []string{}
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
			if field == nil && want.extension {
				unbuilt = append(unbuilt, name+"."+want.name)
				continue
			}
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
			if value == nil && fence.extensionValues[valueName] {
				unbuilt = append(unbuilt, name+"."+valueName)
				continue
			}
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
		switch {
		case declared[name]:
		case fences.messages[name].compute:
			unbuilt = append(unbuilt, "message "+name)
		default:
			report("message %s is written and no file declares it", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(fences.enums)) {
		switch {
		case declared[name]:
		case fences.enums[name].compute:
			unbuilt = append(unbuilt, "enum "+name)
		default:
			report("enum %s is written and no file declares it", name)
		}
	}
	slices.Sort(unbuilt)
	return differences, unbuilt
}

// §4.9, and the rule that numbers stay as written. What DESIGN-COMPUTE.md writes and no file declares yet is listed,
// never a mismatch, until its task lands (CARCH-M11-04).
func TestDeclarationsMatchTheirFences(t *testing.T) {
	differences, unbuilt := testWireReport(testReadFences(t), protoregistry.GlobalFiles)
	for _, difference := range differences {
		t.Error(difference)
	}
	if 0 < len(unbuilt) {
		t.Logf("DESIGN-COMPUTE.md writes %d declarations, fields and values no file declares yet: %s", len(unbuilt), strings.Join(unbuilt, ", "))
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

// DESIGN-COMPUTE.md's fences, read and placed (CARCH-M11-04): each declaration in the file testComputeFencePlacements
// gives it, the placements naming nothing the fences do not write, and the three extensions joined to the fences they
// extend, their own fields and values marked.
func TestComputeFencesAreReadAndPlaced(t *testing.T) {
	fences := testReadFences(t)
	for name, placement := range testComputeFencePlacements {
		message, enum := fences.messages[name], fences.enums[name]
		switch {
		case message != nil:
			if message.path != placement.path || message.compute == placement.extends {
				t.Errorf("%s is in %s, compute %t; placed in %s, extending %t", name, message.path, message.compute, placement.path, placement.extends)
			}
		case enum != nil:
			if enum.path != placement.path || enum.compute == placement.extends {
				t.Errorf("%s is in %s, compute %t; placed in %s, extending %t", name, enum.path, enum.compute, placement.path, placement.extends)
			}
		default:
			t.Errorf("testComputeFencePlacements places %s, which no fence writes", name)
		}
	}
	extensionNumbers := func(name string) []int32 {
		numbers := []int32{}
		for _, field := range fences.messages[name].fields {
			if field.extension {
				numbers = append(numbers, field.number)
			}
		}
		return testSorted(numbers)
	}
	if got := extensionNumbers("ModelCallBody"); !slices.Equal(got, []int32{11, 12, 13, 14, 15}) {
		t.Errorf("ModelCallBody's extension fields are %v", got)
	}
	if got := extensionNumbers("ApprovalDecision"); !slices.Equal(got, []int32{15, 16}) {
		t.Errorf("ApprovalDecision's extension fields are %v", got)
	}
	channels := fences.enums["ApprovalChannel"]
	if channels.values["APPROVAL_CHANNEL_AUTO"] != 4 || !channels.extensionValues["APPROVAL_CHANNEL_AUTO"] || channels.extensionValues["APPROVAL_CHANNEL_HARNESS"] {
		t.Errorf("ApprovalChannel: %v, extending %v", channels.values, channels.extensionValues)
	}
	if header := fences.messages["ComputeInferHeader"]; len(header.fields) != 9 || header.path != "protocol/infer.proto" {
		t.Errorf("ComputeInferHeader: %+v", header)
	}
}

// What a compute fence writes and no file declares is unbuilt, never a difference: a compute-only message, and a field a
// fence adds to a declared message; the same field without its mark is a difference, so the mark is what spares it.
func TestComputeFencesUnbuiltAreNoMismatch(t *testing.T) {
	plant := func(extension bool) *testFences {
		fences := testReadFences(t)
		fences.messages["PlantedCompute"] = &testFenceMessage{
			path: "protocol/types.proto", compute: true,
			fields: []testFenceField{{name: "planted", number: 1, typeName: "uint32"}},
		}
		readerKey := fences.messages["ReaderKey"]
		readerKey.fields = append(readerKey.fields, testFenceField{name: "planted_extension", number: 99, typeName: "bytes", extension: extension})
		return fences
	}
	differences, unbuilt := testWireReport(plant(true), protoregistry.GlobalFiles)
	if len(differences) != 0 {
		t.Errorf("differences: %v", differences)
	}
	for _, want := range []string{"message PlantedCompute", "ReaderKey.planted_extension"} {
		if !slices.Contains(unbuilt, want) {
			t.Errorf("%s is not unbuilt: %v", want, unbuilt)
		}
	}
	differences, _ = testWireReport(plant(false), protoregistry.GlobalFiles)
	if !testHasDifference(differences, "ReaderKey.planted_extension is written and not declared") {
		t.Errorf("an unmarked field passed: %v", differences)
	}
}

// A descriptor type for a fence's scalar type name.
func testScalarFieldType(t testing.TB, typeName string) descriptorpb.FieldDescriptorProto_Type {
	types := map[string]descriptorpb.FieldDescriptorProto_Type{
		"bool": descriptorpb.FieldDescriptorProto_TYPE_BOOL, "bytes": descriptorpb.FieldDescriptorProto_TYPE_BYTES,
		"string": descriptorpb.FieldDescriptorProto_TYPE_STRING, "uint32": descriptorpb.FieldDescriptorProto_TYPE_UINT32,
		"uint64": descriptorpb.FieldDescriptorProto_TYPE_UINT64, "int64": descriptorpb.FieldDescriptorProto_TYPE_INT64,
		"int32": descriptorpb.FieldDescriptorProto_TYPE_INT32,
	}
	fieldType, ok := types[typeName]
	if !ok {
		t.Fatalf("no scalar type %s", typeName)
	}
	return fieldType
}

// Once a file declares a compute message as its fence writes it, it is compared whole: built as written it differs in
// nothing and is no longer unbuilt, and a planted number change in the copy fails, for a compute-only message and for
// an extension's field alike. The copy declares what the real files do not yet, and changes what they do.
func TestComputeFenceCatchesAPlantedNumberChange(t *testing.T) {
	fences := testReadFences(t)
	header := fences.messages["ComputeInferHeader"]
	route := slices.IndexFunc(fences.messages["ModelCallBody"].fields, func(field testFenceField) bool { return field.name == "route" })
	if route < 0 {
		t.Fatal("ModelCallBody's fences write no route")
	}
	routeField := fences.messages["ModelCallBody"].fields[route]
	plant := func(headerModelNumber int32, routeNumber int32) *protoregistry.Files {
		return testPlantedFiles(t, func(fileProtos testFileProtos) {
			var message *descriptorpb.DescriptorProto
			if file := fileProtos[header.path]; file != nil {
				message = testPlantedMessage(t, fileProtos, header.path, "ComputeInferHeader")
			} else {
				message = &descriptorpb.DescriptorProto{Name: proto.String("ComputeInferHeader")}
				// as protoc registers a file of this package, go_package and all
				options := proto.Clone(fileProtos["protocol/types.proto"].GetOptions()).(*descriptorpb.FileOptions)
				fileProtos[header.path] = &descriptorpb.FileDescriptorProto{
					Name: proto.String(header.path), Package: proto.String(testProtoPackage), Syntax: proto.String("proto3"),
					Options: options, MessageType: []*descriptorpb.DescriptorProto{message},
				}
			}
			message.Field = nil
			for _, field := range header.fields {
				number := field.number
				if field.name == "model" {
					number = headerModelNumber
				}
				message.Field = append(message.Field, testNewField(field.name, number, testScalarFieldType(t, field.typeName)))
			}
			modelCall := testPlantedMessage(t, fileProtos, "protocol/record.proto", "ModelCallBody")
			modelCall.Field = slices.DeleteFunc(modelCall.Field, func(field *descriptorpb.FieldDescriptorProto) bool {
				return field.GetName() == routeField.name
			})
			modelCall.Field = append(modelCall.Field, testNewField(routeField.name, routeNumber, testScalarFieldType(t, routeField.typeName)))
		})
	}

	differences, unbuilt := testWireReport(fences, plant(2, routeField.number))
	for _, difference := range differences {
		if strings.Contains(difference, "ComputeInferHeader") || strings.Contains(difference, "ModelCallBody.route") {
			t.Errorf("declared as written, and still: %s", difference)
		}
	}
	if slices.Contains(unbuilt, "message ComputeInferHeader") || slices.Contains(unbuilt, "ModelCallBody.route") {
		t.Errorf("declared, and still unbuilt: %v", unbuilt)
	}

	differences, _ = testWireReport(fences, plant(19, 22))
	for _, want := range []string{"ComputeInferHeader.model is 19, and its fence writes 2", "ModelCallBody.route is 22, and its fence writes 12"} {
		if !testHasDifference(differences, want) {
			t.Errorf("wanted %q, found %v", want, differences)
		}
	}
}

// The join's own checks, on fences planted for it: what it cannot join is a finding, never a quiet second copy.
func TestComputeFenceJoinRefusesWhatItCannotJoin(t *testing.T) {
	base := func() *testFences {
		return &testFences{
			messages: map[string]*testFenceMessage{
				"Kept": {path: "protocol/record.proto", fields: []testFenceField{{name: "kept", number: 1, typeName: "uint32"}}, reservedNumbers: []int32{9}},
			},
			enums: map[string]*testFenceEnum{
				"KeptEnum": {path: "protocol/record.proto", values: map[string]int32{"KEPT_NONE": 0}},
			},
		}
	}
	extending := map[string]testComputeFencePlacement{
		"Kept": {path: "protocol/record.proto", extends: true}, "KeptEnum": {path: "protocol/record.proto", extends: true},
		"Missing": {path: "protocol/record.proto", extends: true},
	}
	writing := map[string]testComputeFencePlacement{"Kept": {path: "protocol/record.proto"}, "Fresh": {path: "protocol/infer.proto"}}
	cases := []struct {
		name       string
		compute    *testFences
		placements map[string]testComputeFencePlacement
		findings   int
	}{
		{
			name: "a message written twice",
			compute: &testFences{enums: map[string]*testFenceEnum{}, messages: map[string]*testFenceMessage{
				"Kept": {path: "protocol/record.proto", fields: []testFenceField{{name: "added", number: 2, typeName: "uint32"}}},
			}},
			placements: writing, findings: 1,
		},
		{
			name: "an extension of nothing",
			compute: &testFences{enums: map[string]*testFenceEnum{}, messages: map[string]*testFenceMessage{
				"Missing": {path: "protocol/record.proto", fields: []testFenceField{{name: "added", number: 2, typeName: "uint32"}}},
			}},
			placements: extending, findings: 1,
		},
		{
			name: "an extension elsewhere",
			compute: &testFences{enums: map[string]*testFenceEnum{}, messages: map[string]*testFenceMessage{
				"Kept": {path: "protocol/infer.proto", fields: []testFenceField{{name: "added", number: 2, typeName: "uint32"}}},
			}},
			placements: extending, findings: 1,
		},
		{
			name: "an extension's name, number and reserved number taken, beside one that joins",
			compute: &testFences{enums: map[string]*testFenceEnum{}, messages: map[string]*testFenceMessage{
				"Kept": {path: "protocol/record.proto", fields: []testFenceField{
					{name: "kept", number: 2, typeName: "uint32"}, {name: "again", number: 1, typeName: "uint32"},
					{name: "reserved", number: 9, typeName: "uint32"}, {name: "added", number: 3, typeName: "uint32"},
				}},
			}},
			placements: extending, findings: 3,
		},
		{
			name: "an enum extension's value taken, beside one that joins",
			compute: &testFences{messages: map[string]*testFenceMessage{}, enums: map[string]*testFenceEnum{
				"KeptEnum": {path: "protocol/record.proto", values: map[string]int32{"KEPT_NONE": 0, "KEPT_AGAIN": 0, "KEPT_ADDED": 1}},
			}},
			placements: extending, findings: 2,
		},
	}
	for _, c := range cases {
		if findings := testJoinComputeFences(base(), c.compute, c.placements); len(findings) != c.findings {
			t.Errorf("%s: %d findings, want %d: %v", c.name, len(findings), c.findings, findings)
		}
	}
	// what joins: a fresh message whole, marked compute; an extension's free field and value, marked
	fences := base()
	compute := &testFences{
		messages: map[string]*testFenceMessage{
			"Fresh": {path: "protocol/infer.proto", fields: []testFenceField{{name: "fresh", number: 1, typeName: "uint32"}}},
			"Kept":  {path: "protocol/record.proto", fields: []testFenceField{{name: "added", number: 3, typeName: "uint32"}}},
		},
		enums: map[string]*testFenceEnum{"KeptEnum": {path: "protocol/record.proto", values: map[string]int32{"KEPT_ADDED": 1}}},
	}
	placements := map[string]testComputeFencePlacement{
		"Fresh": {path: "protocol/infer.proto"}, "Kept": {path: "protocol/record.proto", extends: true},
		"KeptEnum": {path: "protocol/record.proto", extends: true},
	}
	if findings := testJoinComputeFences(fences, compute, placements); len(findings) != 0 {
		t.Fatalf("findings: %v", findings)
	}
	kept := fences.messages["Kept"]
	if !fences.messages["Fresh"].compute || kept.compute || len(kept.fields) != 2 || !kept.fields[1].extension || kept.fields[0].extension {
		t.Errorf("joined %+v and %+v", fences.messages["Fresh"], kept)
	}
	if enum := fences.enums["KeptEnum"]; enum.values["KEPT_ADDED"] != 1 || !enum.extensionValues["KEPT_ADDED"] || enum.extensionValues["KEPT_NONE"] {
		t.Errorf("joined %+v", enum)
	}
}
