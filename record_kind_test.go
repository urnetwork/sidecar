//go:build !js

// Holds record_kind.go to RECORD.md: section 6.3's registry, section 8's classes, section 6.2's enumerations and
// section 6.4's bodies, read from the document itself, so a row changed in one and not the other fails here (section
// 20's registry row). The js leg opens no files, so these stay off it, as record_md_test.go does.

package sidecar

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// Every kind section 6.3 lists takes its number, name and class here, and every kind here that a header may carry
// is a row there.
func TestRecordKindsMatchSectionSixThree(t *testing.T) {
	doc := newRecordMd(t)
	rows := doc.registry(t)
	for name, row := range rows {
		kind, ok := RecordKindNamed(name)
		if !ok {
			t.Errorf("section 6.3's %s has no kind here", name)
			continue
		}
		if int(kind) != row.number {
			t.Errorf("%s is %d here and %d in section 6.3", name, kind, row.number)
		}
		if kind.String() != name {
			t.Errorf("kind %d reads %q", row.number, kind.String())
		}
		if kind.Class().String() != row.class {
			t.Errorf("%s is class %s here and %s in section 6.3", name, kind.Class(), row.class)
		}
		if !kind.Writable() {
			t.Errorf("%s is not writable", name)
		}
	}
	writableCount := 0
	for _, kind := range RecordKinds() {
		if !kind.Writable() {
			continue
		}
		writableCount += 1
		if _, ok := rows[kind.String()]; !ok {
			t.Errorf("kind %d %s is not in section 6.3", kind, kind)
		}
	}
	if writableCount != len(rows) {
		t.Errorf("%d writable kinds here and %d rows in section 6.3", writableCount, len(rows))
	}

	// The derived names, which section 6.3 gives in a sentence after its table.
	derived := regexp.MustCompile("(\\d+) `([a-z_]+)`").FindAllStringSubmatch(recordMdFlat(doc.section(t, "6.3")), -1)
	derivedCount := 0
	for _, match := range derived {
		number, err := strconv.Atoi(match[1])
		if err != nil || number < 64 || 79 < number {
			continue
		}
		derivedCount += 1
		kind := RecordKind(number)
		if kind.String() != match[2] || !kind.Known() || !kind.Derived() || kind.Writable() {
			t.Errorf("derived name %d reads %q, known %v, derived %v, writable %v", number, kind, kind.Known(), kind.Derived(), kind.Writable())
		}
	}
	if derivedCount != 3 {
		t.Errorf("section 6.3 gives %d derived names", derivedCount)
	}
}

// Section 8's class rows give each class its number and name.
func TestRecordClassesMatchSectionEight(t *testing.T) {
	doc := newRecordMd(t)
	classRow := regexp.MustCompile(`^(?:class)? +(\d) ([a-z]+) +`)
	found := 0
	for _, line := range strings.Split(doc.section(t, "8"), "\n") {
		match := classRow.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		number, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		found += 1
		class := RecordClass(number)
		if class.String() != match[2] || !class.Known() {
			t.Errorf("class %d reads %q here and %s in section 8", number, class, match[2])
		}
	}
	if found != 7 {
		t.Errorf("section 8 holds %d classes", found)
	}
	if RecordClass(0).Known() || RecordClass(8).Known() {
		t.Error("a class section 8 does not hold reads as known")
	}

	// "an unknown kind takes class 2"
	recordMdRequire(t, "section 8", doc.section(t, "8"), "an unknown kind takes class 2")
	for _, kind := range []RecordKind{RecordKindUnspecified, 11, 63, RecordKindRun, 70, 1024, 60000} {
		if kind.Class() != RecordClassAction {
			t.Errorf("kind %d takes class %s", kind, kind.Class())
		}
	}
}

// The value and name pairs of one of section 6.2's rows, cut before its parenthesis.
func testRecordEnumerationRow(t *testing.T, doc *recordMd, key string) map[int]string {
	row := doc.row(t, "6.2", key)
	if row == "" {
		t.Fatalf("section 6.2 has no row %s", key)
	}
	values, _, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(row, key)), " (")
	pairs := map[int]string{}
	for _, part := range strings.Split(values, ", ") {
		numberText, name, ok := strings.Cut(part, " ")
		number, err := strconv.Atoi(numberText)
		if !ok || err != nil {
			t.Fatalf("section 6.2's %s holds %q", key, part)
		}
		pairs[number] = name
	}
	return pairs
}

// Section 6.2's enumerations, each value with its name, here and in record.proto's enums.
func TestRecordEnumerationsMatchSectionSixTwo(t *testing.T) {
	doc := newRecordMd(t)

	sources := testRecordEnumerationRow(t, doc, "RecordHeader.source")
	if len(sources) != 4 {
		t.Errorf("section 6.2 gives %d sources", len(sources))
	}
	for number, name := range sources {
		if source := RecordSource(number); source.String() != name || !source.Known() {
			t.Errorf("source %d reads %q here and %s in section 6.2", number, source, name)
		}
	}
	if RecordSourceUnknown.Known() {
		t.Error("source 0 reads as known")
	}

	agentSources := testRecordEnumerationRow(t, doc, "RecordHeader.agent_source")
	if len(agentSources) != 3 || agentSources[0] != "no agent" {
		t.Errorf("section 6.2 gives agent sources %v", agentSources)
	}
	for number, name := range agentSources {
		if number == 0 {
			name = "none"
		}
		if agentSource := RecordAgentSource(number); agentSource.String() != name || !agentSource.Known() {
			t.Errorf("agent source %d reads %q here and %s in section 6.2", number, agentSource, name)
		}
	}

	reachKinds := testRecordEnumerationRow(t, doc, "ReachReceipt.kind")
	if len(reachKinds) != 6 {
		t.Errorf("section 6.2 gives %d reach kinds", len(reachKinds))
	}
	for number, name := range reachKinds {
		if reachKind := RecordReachKind(number); reachKind.String() != name || !reachKind.Known() {
			t.Errorf("reach kind %d reads %q here and %s in section 6.2", number, reachKind, name)
		}
	}

	// The two record.proto enums section 6.2 numbers: every value it writes, and no other but 0.
	enumCases := []struct {
		key    string
		prefix string
		names  map[int32]string
	}{
		{key: "ApprovalDecision.decision", prefix: "APPROVAL_VERDICT_", names: protocol.ApprovalVerdict_name},
		{key: "ApprovalDecision.channel", prefix: "APPROVAL_CHANNEL_", names: protocol.ApprovalChannel_name},
	}
	for _, c := range enumCases {
		pairs := testRecordEnumerationRow(t, doc, c.key)
		if len(c.names) != len(pairs)+1 {
			t.Errorf("%s: record.proto holds %d values and section 6.2 %d besides 0", c.key, len(c.names), len(pairs))
		}
		for number, name := range pairs {
			if got := strings.ToLower(strings.TrimPrefix(c.names[int32(number)], c.prefix)); got != name {
				t.Errorf("%s %d is %q in record.proto and %s in section 6.2", c.key, number, got, name)
			}
		}
		if c.names[0] != c.prefix+"UNSPECIFIED" {
			t.Errorf("%s's 0 is %q", c.key, c.names[0])
		}
	}
}

// Section 6.1's number rules: 0 never written, private use shown generically and never refused, derived names in
// search alone.
func TestRecordKindNumbersKeepSectionSixOne(t *testing.T) {
	if RecordKindUnspecified.Writable() || RecordKindUnspecified.Known() {
		t.Error("kind 0 is writable or known")
	}
	if RecordKindUnspecified.String() != "kind 0" {
		t.Errorf("kind 0 reads %q", RecordKindUnspecified)
	}
	for _, kind := range []RecordKind{1024, 1025, 60000} {
		if !kind.PrivateUse() || kind.Known() || kind.Writable() {
			t.Errorf("kind %d: private %v, known %v, writable %v", kind, kind.PrivateUse(), kind.Known(), kind.Writable())
		}
		if kind.String() != "kind "+strconv.Itoa(int(kind)) {
			t.Errorf("kind %d reads %q", kind, kind)
		}
		if _, ok := kind.NewBody(); ok {
			t.Errorf("kind %d has a body here", kind)
		}
	}
	if RecordKind(1023).PrivateUse() {
		t.Error("kind 1023 reads as private use")
	}
	for number := 64; number <= 79; number += 1 {
		kind := RecordKind(number)
		if !kind.Derived() || kind.Writable() {
			t.Errorf("kind %d: derived %v, writable %v", number, kind.Derived(), kind.Writable())
		}
		if _, ok := kind.NewBody(); ok {
			t.Errorf("derived kind %d has a body", number)
		}
	}
	if RecordKind(63).Derived() || RecordKind(80).Derived() {
		t.Error("a kind outside 64 to 79 reads as derived")
	}
	// A block's unassigned numbers are kinds this build does not know, kept and shown generically.
	for _, kind := range []RecordKind{11, 15, 30, 44, 54} {
		if kind.Known() || kind.String() != "kind "+strconv.Itoa(int(kind)) {
			t.Errorf("unassigned kind %d reads %q, known %v", kind, kind, kind.Known())
		}
	}
	// Each block holds its own classes (section 6.1's blocks row).
	for _, kind := range RecordKinds() {
		if !kind.Writable() {
			continue
		}
		class := kind.Class()
		var inBlock bool
		switch {
		case kind <= 15:
			inBlock = class == RecordClassCoordination || class == RecordClassAnnounce || class == RecordClassRequest
		case kind <= 47:
			inBlock = class == RecordClassAction || class == RecordClassAccounting || class == RecordClassLog
		case kind <= 63:
			inBlock = class == RecordClassCapture
		}
		if !inBlock {
			t.Errorf("kind %d %s of class %s sits outside its block", kind, kind, class)
		}
	}
}

// A message's leading comment in RECORD.md's proto fences: `message X { // comment`, or a one-line message with its
// comment after the brace.
var testRecordMessageComment = regexp.MustCompile(`^message ([A-Za-z0-9_]+) \{.*?//\s*(.*)$`)

// What section 6.4's table writes: a kind, then "Signed " for a stored Signed, then the message.
var testRecordBodyCell = regexp.MustCompile(`([a-z_]+)\s+(Signed )?([A-Z][A-Za-z]+) \(§`)

// Every kind's one body, as RECORD.md gives it: section 6.4's table of DESIGN.md's messages, and each of its own
// messages whose comment opens with the kinds it is the body of.
func TestRecordBodiesMatchSectionSixFour(t *testing.T) {
	doc := newRecordMd(t)
	rows := doc.registry(t)
	type body struct {
		message string
		signed  bool
	}
	kindBodies := map[string]body{}
	add := func(kind string, message string, signed bool) {
		if held, ok := kindBodies[kind]; ok {
			t.Errorf("RECORD.md gives %s two bodies, %s and %s", kind, held.message, message)
		}
		kindBodies[kind] = body{message: message, signed: signed}
	}
	section := doc.section(t, "6.4")
	table, _, _ := strings.Cut(section, "```proto")
	for _, match := range testRecordBodyCell.FindAllStringSubmatch(table, -1) {
		add(match[1], match[3], match[2] != "")
	}
	fenced := false
	for _, line := range strings.Split(doc.text, "\n") {
		if strings.HasPrefix(line, "```") {
			fenced = strings.HasPrefix(line, "```proto")
			continue
		}
		match := testRecordMessageComment.FindStringSubmatch(line)
		if !fenced || match == nil {
			continue
		}
		head := match[2]
		for _, separator := range []string{":", " (", ";"} {
			head, _, _ = strings.Cut(head, separator)
		}
		names := strings.Split(head, ", ")
		allKinds := true
		for _, name := range names {
			if _, ok := rows[name]; !ok {
				allKinds = false
			}
		}
		if !allKinds {
			continue
		}
		for _, name := range names {
			add(name, match[1], false)
		}
	}

	for name := range rows {
		want, ok := kindBodies[name]
		if !ok {
			t.Errorf("RECORD.md gives %s no body", name)
			continue
		}
		kind, _ := RecordKindNamed(name)
		message, ok := kind.NewBody()
		if !ok {
			t.Errorf("%s has no body here", name)
			continue
		}
		got := string(proto.MessageName(message).Name())
		signedMessage, signedType, signed := kind.NewSignedBody()
		if signed != want.signed {
			t.Errorf("%s: a Signed body here %v, in RECORD.md %v", name, signed, want.signed)
			continue
		}
		if signed {
			if got != "Signed" {
				t.Errorf("%s's stored body is %s, not a Signed", name, got)
			}
			got = string(proto.MessageName(signedMessage).Name())
			if !strings.HasSuffix(strings.ToLower(strings.ReplaceAll(signedType.String(), "_", "")), strings.ToLower(got)) {
				t.Errorf("%s's Signed is %s around %s", name, signedType, got)
			}
		}
		if got != want.message {
			t.Errorf("%s's body is %s here and %s in RECORD.md", name, got, want.message)
		}
	}
	if len(kindBodies) != len(rows) {
		t.Errorf("RECORD.md gives %d bodies for %d kinds", len(kindBodies), len(rows))
	}
}

// Every body message names its package's type, so a parse never lands in another file's message of the same name.
func TestRecordBodiesAreSidecarMessages(t *testing.T) {
	for _, kind := range RecordKinds() {
		message, ok := kind.NewBody()
		if !ok {
			continue
		}
		name := proto.MessageName(message)
		if name.Parent() != protoreflect.FullName("urnetwork.sidecar") {
			t.Errorf("%s's body is %s", kind, name)
		}
	}
}

// CORE-M1-01's Go types take record.proto's numbers (plan-MCP-wire-enum-numbers), each value and no other.
func TestSidecarActionKindsTakeTheProtoNumbers(t *testing.T) {
	kindCases := []struct {
		kind SidecarActionKind
		name string
	}{
		{kind: SidecarActionPublish, name: "SIDECAR_ACTION_KIND_PUBLISH"},
		{kind: SidecarActionListen, name: "SIDECAR_ACTION_KIND_LISTEN"},
		{kind: SidecarActionForward, name: "SIDECAR_ACTION_KIND_FORWARD"},
		{kind: SidecarActionExpose, name: "SIDECAR_ACTION_KIND_EXPOSE"},
		{kind: SidecarActionEgressChange, name: "SIDECAR_ACTION_KIND_EGRESS_CHANGE"},
		{kind: SidecarActionInvite, name: "SIDECAR_ACTION_KIND_INVITE"},
		{kind: SidecarActionShare, name: "SIDECAR_ACTION_KIND_SHARE"},
		{kind: SidecarActionAliasCreate, name: "SIDECAR_ACTION_KIND_ALIAS_CREATE"},
		{kind: SidecarActionAliasDelete, name: "SIDECAR_ACTION_KIND_ALIAS_DELETE"},
		{kind: SidecarActionAgentConfigWrite, name: "SIDECAR_ACTION_KIND_AGENT_CONFIG_WRITE"},
		{kind: SidecarActionAgentConfigDelete, name: "SIDECAR_ACTION_KIND_AGENT_CONFIG_DELETE"},
		{kind: SidecarActionDnsSet, name: "SIDECAR_ACTION_KIND_DNS_SET"},
		{kind: SidecarActionDnsDelete, name: "SIDECAR_ACTION_KIND_DNS_DELETE"},
		{kind: SidecarActionMail, name: "SIDECAR_ACTION_KIND_MAIL_SEND"},
		{kind: SidecarActionAccessRequest, name: "SIDECAR_ACTION_KIND_ACCESS_REQUEST"},
		{kind: SidecarActionPayment, name: "SIDECAR_ACTION_KIND_PAYMENT"},
		{kind: SidecarActionRestore, name: "SIDECAR_ACTION_KIND_RESTORE"},
	}
	for _, c := range kindCases {
		value, ok := protocol.SidecarActionKind_value[c.name]
		if !ok || value != int32(c.kind) {
			t.Errorf("%s is %d in record.proto and %d here", c.name, value, c.kind)
		}
	}
	if len(protocol.SidecarActionKind_value) != len(kindCases)+1 || int32(SidecarActionUnspecified) != 0 {
		t.Errorf("record.proto holds %d action kinds, and the root %d besides 0", len(protocol.SidecarActionKind_value), len(kindCases))
	}

	riskCases := []struct {
		risk SidecarRisk
		name string
	}{
		{risk: SidecarRiskNormal, name: "SIDECAR_RISK_NORMAL"},
		{risk: SidecarRiskHigh, name: "SIDECAR_RISK_HIGH"},
	}
	for _, c := range riskCases {
		value, ok := protocol.SidecarRisk_value[c.name]
		if !ok || value != int32(c.risk) {
			t.Errorf("%s is %d in record.proto and %d here", c.name, value, c.risk)
		}
	}
	if len(protocol.SidecarRisk_value) != len(riskCases)+1 || int32(SidecarRiskUnspecified) != 0 {
		t.Errorf("record.proto holds %d risks, and the root %d besides 0", len(protocol.SidecarRisk_value), len(riskCases))
	}
}
