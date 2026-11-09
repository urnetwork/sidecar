// §16.11's field classes, caps and redaction for the team directory, on every leg, sidecar_http included: what each
// field of directory.proto's messages may hold and how much of it, so a writer refuses an overrun before it signs and
// a reader ignores a version past one and alarms (record_alarm over_cap), both through the same checks.
//
//	attested    ids, kinds, times, states, the tainted and private bits and roles: here their lengths and the values
//	            directory.proto names; readers check them against §7.9's state (RECORD-M6-12) and show their own
//	            config's names, so member_label and host_label, the writer's view kept for the index, are held to
//	            their caps and charsets here and never redacted
//	identifier  agent labels, harnesses, model, project, branch, claim targets, topics and service names: a label
//	            [a-z0-9-], a branch by git check-ref-format --branch, a service name by its kind's grammar, and the
//	            rest path text, in NFC with no control, invisible format character, line separator or whitespace run
//	            (record-m6-11-identifier-invisible-characters keeps the invisible characters refused meanwhile)
//	prose       title, description, claim text, handoff note, request reason and decision note: NFC, with no C0 or
//	            C1 control and no bidi control
//
// The daemon runs §16.7's redactor over every identifier and prose field before it signs, and a matching field
// becomes [REDACTED:<rule>], whole: with no HMAC, since every member reads this text, and never in part, so a rule
// that misses a secret's edge leaves none of it. A field that is exactly one such marker passes its class.
// DirectoryRedact normalizes before the redactor reads: a character dropped after redaction could join a secret the
// redactor never saw whole.
//
// Identifier fields can still carry short words, a disclosed residual: the charset is the limit, never a content
// filter. Every cap here is directory.proto's, a format value and not a tunable, and no error here carries a field's
// value.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// directory.proto's caps, in bytes of UTF-8 or in entries.
const (
	// AnnounceWho.agent_label, Handoff.to_agent_label, AnnounceWhat.agent_labels' and harnesses' entries, and
	// AnnounceWho.harness: [a-z0-9-]{1,64}.
	DirectoryLabelByteCount = 64
	// AnnounceWhat.topics' entries: [a-z0-9-]{1,32}.
	DirectoryTopicByteCount = 32
	DirectoryModelByteCount = 64
	// The writer's view of its member's name, for the index.
	DirectoryMemberLabelByteCount = 64
	// The sidecar's config name (§7.7), a DNS label.
	DirectoryHostLabelByteCount = 63
	DirectoryProjectByteCount   = 128
	DirectoryBranchByteCount    = 128
	// A run's title, after redaction.
	DirectoryRunTitleByteCount = 120
	// A repo's display name.
	DirectoryRepoTitleByteCount          = 128
	DirectoryDescriptionByteCount        = 512
	DirectoryServiceDescriptionByteCount = 256
	DirectoryClaimTextByteCount          = 512
	DirectoryClaimTargetByteCount        = 256
	DirectoryHandoffNoteByteCount        = 512
	DirectoryReasonByteCount             = 512
	DirectoryDecisionNoteByteCount       = 512

	DirectoryClaimCount            = 4
	DirectoryClaimTargetCount      = 16
	DirectoryWorkerHarnessCount    = 8
	DirectoryWorkerAgentLabelCount = 16
	DirectoryServiceCount          = 32
	DirectoryTopicCount            = 8
	// A request's tcp_ports, which name a worker's announced bridge ports, at most its services.
	DirectoryRequestPortCount = DirectoryServiceCount
)

// The grammars service names take: §9.4's socket name and a DNS name.
const (
	directorySocketNameByteCount = 112
	directoryHostNameByteCount   = 253
	// A bridge port's name, tcp:<port>.
	directoryBridgePortPrefix = "tcp:"
)

// A field that is exactly one shared marker, which DirectoryRedact leaves where a field matched.
var directorySharedMarkerPattern = regexp.MustCompile(`^\[REDACTED:[a-z0-9-]{1,64}\]$`)

// Either marker form, the rule its group: a field holding one takes the shared form whole, so no HMAC a local
// redaction wrote reaches the directory.
var directoryAnyMarkerPattern = regexp.MustCompile(`\[REDACTED:([a-z0-9-]+)(?::[0-9a-f]{8})?\]`)

// A refusal, naming the field and never its value.
func directoryRefusal(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDirectoryFormatInvalid}, args...)...)
}

// Whether text is exactly one shared marker, [REDACTED:<rule>].
func directorySharedMarker(text string) bool {
	return directorySharedMarkerPattern.MatchString(text)
}

// Whether text is a label of at most maxByteCount bytes, [a-z0-9-]{1,maxByteCount}.
func directoryLabelValid(text string, maxByteCount int) bool {
	return len(text) != 0 && len(text) <= maxByteCount && isDnsLowerBytes(text, "-")
}

// Whether character is one no identifier holds: a C0 or C1 control; a format character, which holds the bidi
// controls, the zero-width characters, U+FEFF and the tag characters; a variation selector or another
// default-ignorable code point; or a line or paragraph separator. Each either acts on the text around it or shows
// nothing to a person while a model still reads it.
func directoryIdentifierCharacterRefused(character rune) bool {
	return unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
		unicode.Is(unicode.Variation_Selector, character) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, character) ||
		unicode.In(character, unicode.Zl, unicode.Zp)
}

// Whether text is path text of at most maxByteCount bytes: valid UTF-8 in NFC, holding no character
// directoryIdentifierCharacterRefused names and no run of two whitespace characters. Empty text is path text.
func directoryIdentifierTextValid(text string, maxByteCount int) bool {
	if maxByteCount < len(text) || !utf8.ValidString(text) {
		return false
	}
	space := false
	for _, character := range text {
		if directoryIdentifierCharacterRefused(character) {
			return false
		}
		isSpace := unicode.IsSpace(character)
		if isSpace && space {
			return false
		}
		space = isSpace
	}
	return norm.NFC.IsNormalString(text)
}

// Whether text is a branch name: path text that git check-ref-format --branch takes, at most
// DirectoryBranchByteCount bytes. git's rules: no component beginning with a dot or ending in .lock, no empty
// component, no .., no @{, no ASCII control, space, ~, ^, :, ?, *, [ or \, not ending in a dot, not @ alone, and as a
// branch, not beginning with a dash and not HEAD.
func directoryBranchValid(text string) bool {
	if text == "" || !directoryIdentifierTextValid(text, DirectoryBranchByteCount) {
		return false
	}
	if text[0] == '-' || text == "HEAD" || text == "@" || strings.HasSuffix(text, ".") ||
		strings.Contains(text, "..") || strings.Contains(text, "@{") {
		return false
	}
	for index := range len(text) {
		character := text[index]
		if character <= ' ' || character == 0x7f || strings.IndexByte("~^:?*[\\", character) != -1 {
			return false
		}
	}
	for _, component := range strings.Split(text, "/") {
		if component == "" || component[0] == '.' || strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	return true
}

// Whether text is prose of at most maxByteCount bytes: valid UTF-8 in NFC with no C0 or C1 control and no bidi
// control.
func directoryProseValid(text string, maxByteCount int) bool {
	if maxByteCount < len(text) || !utf8.ValidString(text) {
		return false
	}
	for _, character := range text {
		if unicode.IsControl(character) || unicode.Is(unicode.Bidi_Control, character) {
			return false
		}
	}
	return norm.NFC.IsNormalString(text)
}

// Whether a C0 or C1 control breaks a line or a word: a tab, a line feed, a vertical tab, a form feed, a carriage
// return or a next line.
func directoryBreakingControl(character rune) bool {
	switch character {
	case '\t', '\n', '\v', '\f', '\r', 0x85:
		return true
	}
	return false
}

// text as §16.11's prose: each invalid UTF-8 byte U+FFFD, each control that breaks a line or a word a space, so the
// words either side stay apart, every other C0 or C1 control and every bidi control dropped, then NFC. Dropping comes
// first, since a dropped character between a letter and its mark would otherwise leave them apart, out of NFC. The
// result passes the prose class whatever text is, and normalizing it again changes nothing. It is not cut: a writer
// cuts a run's title to its cap after redaction, and refuses any other prose over its cap.
func DirectoryNormalizeProse(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	for _, character := range text {
		switch {
		case directoryBreakingControl(character):
			builder.WriteByte(' ')
		case unicode.IsControl(character), unicode.Is(unicode.Bidi_Control, character):
		default:
			builder.WriteRune(character)
		}
	}
	return norm.NFC.String(builder.String())
}

// text as path text: each invalid UTF-8 byte U+FFFD, each run of whitespace and line breaks one space, every
// other character directoryIdentifierCharacterRefused names dropped, trimmed, then NFC. The result passes
// directoryIdentifierTextValid at any length; a writer still refuses one over its cap.
func directoryNormalizeIdentifierText(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	space := false
	for _, character := range text {
		switch {
		case unicode.IsSpace(character), directoryBreakingControl(character), unicode.In(character, unicode.Zl, unicode.Zp):
			space = builder.Len() != 0
		case directoryIdentifierCharacterRefused(character):
		default:
			if space {
				builder.WriteByte(' ')
				space = false
			}
			builder.WriteRune(character)
		}
	}
	return norm.NFC.String(builder.String())
}

// Whether text is a lowercase LDH DNS name of at most 253 bytes: one or more labels joined by dots.
func directoryHostNameValid(text string) bool {
	if text == "" || directoryHostNameByteCount < len(text) {
		return false
	}
	for _, label := range strings.Split(text, ".") {
		if !isDnsLowerLdhLabel(label) {
			return false
		}
	}
	return true
}

// Whether text is a bridge port's name, tcp:<port>, the port 1 to 65,535 in decimal with no leading zero.
func directoryBridgePortValid(text string) bool {
	portText, ok := strings.CutPrefix(text, directoryBridgePortPrefix)
	if !ok || portText == "" || portText[0] == '0' {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port != 0 && strconv.FormatUint(port, 10) == portText
}

// Whether name is what a service of kind is named by: an application socket's §9.4 name in its canonical form, a
// published TLS host's DNS name, or a bridge port's tcp:<port>.
func directoryServiceNameValid(kind DirectoryServiceKind, name string) bool {
	switch kind {
	case DirectoryServiceKindSocket:
		if directorySocketNameByteCount < len(name) {
			return false
		}
		canonical, namespace, err := ParseSocketName(name)
		return err == nil && canonical == name && namespace == SocketNamespaceApplication
	case DirectoryServiceKindTlsHost:
		return directoryHostNameValid(name)
	case DirectoryServiceKindBridgePort:
		return directoryBridgePortValid(name)
	}
	return false
}

// Whether an identifier field holds an id of 16 bytes, or nothing where optional.
func directoryIdValid(value []byte, optional bool) bool {
	return len(value) == recordIdByteCount || (optional && len(value) == 0)
}

// The identifier classes, by what each field's text must pass, a whole shared marker passing every one.
type directoryIdentifierClass int

const (
	// [a-z0-9-]{1,cap}
	directoryIdentifierLabel directoryIdentifierClass = iota + 1
	// path text, possibly empty
	directoryIdentifierText
	// git check-ref-format --branch
	directoryIdentifierBranch
)

// Whether text passes class within maxByteCount, or is exactly one shared marker within it.
func directoryIdentifierValid(class directoryIdentifierClass, text string, maxByteCount int) bool {
	if len(text) <= maxByteCount && directorySharedMarker(text) {
		return true
	}
	switch class {
	case directoryIdentifierLabel:
		return directoryLabelValid(text, maxByteCount)
	case directoryIdentifierText:
		return directoryIdentifierTextValid(text, maxByteCount)
	case directoryIdentifierBranch:
		return len(text) <= maxByteCount && directoryBranchValid(text)
	}
	return false
}

// One field DirectoryRedact replaced, named by its place in the message and the rule, never by its value.
type DirectoryRedaction struct {
	// As "what.title" or "claims[1].targets[0]".
	Field string
	Rule  string
}

// Normalizes, then redacts, in place, every identifier and prose field of an Announcement, a DirectoryRequest or a
// DirectoryDecision, before its writer signs it (§16.11's redaction row): prose by DirectoryNormalizeProse and path
// text by the identifier class's normalization, so the redactor reads the text as it will be signed; then any field
// in which the redactor finds a secret, or PII while the harness config hashes it, or which holds a marker of either
// form, becomes [REDACTED:<rule>] whole, the rule its earliest. Labels, branches and service names are taken as
// written: a writer that holds one outside its class is refused by the checks after this. A DirectoryErasureRequest
// holds no text. A DirectoryRequest's approval is left alone, since its hashes bind its bytes: its filer builds it
// from text already redacted. Answers what was replaced. Redacting twice changes nothing.
func DirectoryRedact(redactor *Redactor, message proto.Message) ([]DirectoryRedaction, error) {
	if redactor == nil {
		return nil, errors.New("directory redact: no redactor")
	}
	redactions := []DirectoryRedaction{}
	redact := func(field string, value *string) {
		text := *value
		if text == "" || directorySharedMarker(text) {
			return
		}
		rule := ""
		start := len(text)
		if location := directoryAnyMarkerPattern.FindStringSubmatchIndex(text); location != nil {
			rule = text[location[2]:location[3]]
			start = location[0]
		}
		if _, matches := redactor.RedactShared([]byte(text)); len(matches) != 0 && matches[0].Start < start {
			rule = matches[0].Rule
		}
		if rule == "" {
			return
		}
		*value = "[REDACTED:" + rule + "]"
		redactions = append(redactions, DirectoryRedaction{Field: field, Rule: rule})
	}
	prose := func(field string, value *string) {
		*value = DirectoryNormalizeProse(*value)
		redact(field, value)
	}
	text := func(field string, value *string) {
		*value = directoryNormalizeIdentifierText(*value)
		redact(field, value)
	}
	labels := func(field string, values []string) {
		for index := range values {
			redact(fmt.Sprintf("%s[%d]", field, index), &values[index])
		}
	}

	switch typed := message.(type) {
	case *protocol.Announcement:
		if typed == nil {
			return nil, directoryRefusal("no item")
		}
		if who := typed.GetWho(); who != nil {
			redact("who.agent_label", &who.AgentLabel)
			redact("who.harness", &who.Harness)
			text("who.model", &who.Model)
		}
		if what := typed.GetWhat(); what != nil {
			prose("what.title", &what.Title)
			prose("what.description", &what.Description)
			labels("what.harnesses", what.Harnesses)
			labels("what.agent_labels", what.AgentLabels)
			labels("what.topics", what.Topics)
			for index, service := range what.GetServices() {
				if service == nil {
					continue
				}
				redact(fmt.Sprintf("what.services[%d].name", index), &service.Name)
				prose(fmt.Sprintf("what.services[%d].description", index), &service.Description)
			}
		}
		if where := typed.GetWhere(); where != nil {
			text("where.project", &where.Project)
			redact("where.branch", &where.Branch)
		}
		for index, claim := range typed.GetClaims() {
			if claim == nil {
				continue
			}
			prose(fmt.Sprintf("claims[%d].text", index), &claim.Text)
			for targetIndex := range claim.Targets {
				text(fmt.Sprintf("claims[%d].targets[%d]", index, targetIndex), &claim.Targets[targetIndex])
			}
		}
		if handoff := typed.GetHandoff(); handoff != nil {
			redact("handoff.to_agent_label", &handoff.ToAgentLabel)
			prose("handoff.note", &handoff.Note)
		}
	case *protocol.DirectoryRequest:
		if typed == nil {
			return nil, directoryRefusal("no request")
		}
		prose("reason", &typed.Reason)
	case *protocol.DirectoryDecision:
		if typed == nil {
			return nil, directoryRefusal("no decision")
		}
		prose("note", &typed.Note)
	case *protocol.DirectoryErasureRequest:
		if typed == nil {
			return nil, directoryRefusal("no erasure request")
		}
	default:
		return nil, directoryRefusal("%s is no directory message", proto.MessageName(message))
	}
	return redactions, nil
}

// The fields of an item and of its who, what and where that each kind sets (directory.proto's comments). Whatever a
// kind does not set stays empty, so an item carries nothing past its who, what and where (I-20).
var directoryItemFields = map[DirectoryAnnouncementKind]map[protoreflect.Name][]protoreflect.Name{
	DirectoryAnnouncementKindRun: {
		"": {"announcement_id", "kind", "version", "started_millis", "renewed_millis", "expires_millis", "state", "tainted",
			"who", "what", "where", "claims", "handoff"},
		"who":   {"member_id", "sidecar_id", "member_label", "agent_id", "agent_label", "harness", "model"},
		"what":  {"title", "run_id"},
		"where": {"repo_id", "project", "branch", "private", "host_label"},
	},
	DirectoryAnnouncementKindWorker: {
		"": {"announcement_id", "kind", "version", "started_millis", "renewed_millis", "expires_millis", "state", "tainted",
			"who", "what", "where"},
		"who":   {"member_id", "sidecar_id", "member_label", "tag_ids"},
		"what":  {"description", "harnesses", "agent_labels", "services", "requests"},
		"where": {"host_label", "platform", "ephemeral"},
	},
	DirectoryAnnouncementKindRepo: {
		"": {"announcement_id", "kind", "version", "started_millis", "renewed_millis", "state", "tainted", "who", "what",
			"where", "pad"},
		"who":   {"member_id", "sidecar_id", "member_label"},
		"what":  {"title", "description", "requests", "topics", "repo_kind", "roles"},
		"where": {"repo_id", "private", "host_label"},
	},
}

// A withdrawal's fields (plan-RECORD-m6-carrier#1): only announcement_id, kind, version, renewed_millis,
// expires_millis, state and who's member_id and sidecar_id.
var directoryWithdrawalFields = map[protoreflect.Name][]protoreflect.Name{
	"":    {"announcement_id", "kind", "version", "renewed_millis", "expires_millis", "state", "who"},
	"who": {"member_id", "sidecar_id"},
}

// A private repo marker's who, what and where: only who, repo_id, repo_kind and requests (§16.11's private row).
var directoryPrivateMarkerFields = map[protoreflect.Name][]protoreflect.Name{
	"who":   {"member_id", "sidecar_id", "member_label"},
	"what":  {"requests", "repo_kind"},
	"where": {"repo_id", "private"},
}

// Refuses a field of message that allowed does not name: name is the message's place in the item, "" for the item.
func directoryOnlyFields(name protoreflect.Name, message proto.Message, allowed []protoreflect.Name) error {
	reflected := message.ProtoReflect()
	if !reflected.IsValid() {
		return nil
	}
	var refused error
	reflected.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if !slices.Contains(allowed, field.Name()) {
			if name == "" {
				refused = directoryRefusal("%s set on this item", field.Name())
			} else {
				refused = directoryRefusal("%s.%s set on this item", name, field.Name())
			}
			return false
		}
		return true
	})
	return refused
}

// Refuses whatever fields names do not allow on item's who, what and where and on item itself.
func directoryItemOnlyFields(item *protocol.Announcement, fields map[protoreflect.Name][]protoreflect.Name) error {
	for _, part := range []struct {
		name    protoreflect.Name
		message proto.Message
	}{
		{name: "", message: item},
		{name: "who", message: item.GetWho()},
		{name: "what", message: item.GetWhat()},
		{name: "where", message: item.GetWhere()},
	} {
		allowed, ok := fields[part.name]
		if !ok {
			continue
		}
		if err := directoryOnlyFields(part.name, part.message, allowed); err != nil {
			return err
		}
	}
	return nil
}

// Holds an item to §16.11's classes and caps and to directory.proto's form, whatever carries it: an M6 announce
// entry or, from format 2, a card or repo file. A writer refuses what this refuses before it signs; a reader ignores
// such a version and alarms over_cap. Checked here: the kind and its state; ids at their lengths; times, version and
// expiry by the format (DirectoryAnnouncementExpiresMillis), so no item stays active past its format's expiry;
// every field the kind sets, and only those; a withdrawal holding only its own fields; a private repo marker holding
// only who, repo_id, repo_kind and requests; a repo item's announcement_id derived from its repo_id; roles, requests
// and repo kinds by their numbers; each identifier in its class and each prose field in its class, within its cap;
// and the pad zero bytes. Who signed it, and whether its ids name what §7.9's state holds, are the reader's
// (RECORD-M6-12, RECORD-M6-14); AnnounceWhere.platform's numbers wait on record-m3-01-directory-platform-numbers, so
// no value of it is refused here.
func DirectoryCheckItem(item *protocol.Announcement) error {
	if item == nil {
		return directoryRefusal("no item")
	}
	kind := DirectoryAnnouncementKind(item.GetKind())
	if !kind.Known() {
		return directoryRefusal("kind %d", item.GetKind())
	}
	state := DirectoryAnnouncementState(item.GetState())
	if !state.KnownFor(kind) {
		return directoryRefusal("state %d on kind %d", item.GetState(), item.GetKind())
	}
	if !directoryIdValid(item.GetAnnouncementId(), false) {
		return directoryRefusal("an announcement_id of %d bytes", len(item.GetAnnouncementId()))
	}
	if item.GetVersion() == 0 {
		return directoryRefusal("version 0")
	}
	renewedMillis := item.GetRenewedMillis()
	if renewedMillis <= 0 || item.GetStartedMillis() < 0 || renewedMillis < item.GetStartedMillis() {
		return directoryRefusal("started %d and renewed %d", item.GetStartedMillis(), renewedMillis)
	}
	if kind != DirectoryAnnouncementKindRepo && math.MaxInt64-DirectoryWorkerExpiry.Milliseconds() < renewedMillis {
		return directoryRefusal("renewed %d leaves no expiry", renewedMillis)
	}
	expiresMillis, _ := DirectoryAnnouncementExpiresMillis(kind, renewedMillis)
	if item.GetExpiresMillis() != expiresMillis {
		return directoryRefusal("expires %d, not the format's %d", item.GetExpiresMillis(), expiresMillis)
	}
	if !bytes.Equal(item.GetPad(), make([]byte, len(item.GetPad()))) {
		return directoryRefusal("a pad that is not zero bytes")
	}
	who := item.GetWho()
	if !directoryIdValid(who.GetSidecarId(), false) || !directoryIdValid(who.GetMemberId(), true) {
		return directoryRefusal("a who with a sidecar_id of %d bytes and a member_id of %d", len(who.GetSidecarId()), len(who.GetMemberId()))
	}

	if state == DirectoryAnnouncementStateWithdrawn {
		return directoryItemOnlyFields(item, directoryWithdrawalFields)
	}
	if err := directoryItemOnlyFields(item, directoryItemFields[kind]); err != nil {
		return err
	}
	if !directoryIdentifierTextValid(who.GetMemberLabel(), DirectoryMemberLabelByteCount) {
		return directoryRefusal("member_label outside its class")
	}
	where := item.GetWhere()
	if hostLabel := where.GetHostLabel(); hostLabel != "" && !isDnsLowerLdhLabel(hostLabel) {
		return directoryRefusal("host_label is no DNS label")
	}
	switch kind {
	case DirectoryAnnouncementKindRun:
		return directoryCheckRun(item, state)
	case DirectoryAnnouncementKindWorker:
		return directoryCheckWorker(item)
	default:
		return directoryCheckRepo(item)
	}
}

// A run item's own fields.
func directoryCheckRun(item *protocol.Announcement, state DirectoryAnnouncementState) error {
	who := item.GetWho()
	what := item.GetWhat()
	where := item.GetWhere()
	switch {
	case !directoryIdValid(who.GetAgentId(), true):
		return directoryRefusal("an agent_id of %d bytes", len(who.GetAgentId()))
	case who.GetAgentLabel() != "" && !directoryIdentifierValid(directoryIdentifierLabel, who.GetAgentLabel(), DirectoryLabelByteCount):
		return directoryRefusal("agent_label outside [a-z0-9-]{1,64}")
	case !directoryIdentifierValid(directoryIdentifierLabel, who.GetHarness(), DirectoryLabelByteCount):
		return directoryRefusal("harness outside [a-z0-9-]{1,64}")
	case !directoryIdentifierValid(directoryIdentifierText, who.GetModel(), DirectoryModelByteCount):
		return directoryRefusal("model of %d bytes or outside its class", len(who.GetModel()))
	case !directoryProseValid(what.GetTitle(), DirectoryRunTitleByteCount):
		return directoryRefusal("title of %d bytes or outside its class", len(what.GetTitle()))
	case !directoryIdValid(what.GetRunId(), false):
		return directoryRefusal("a run_id of %d bytes", len(what.GetRunId()))
	case !directoryIdValid(where.GetRepoId(), true):
		return directoryRefusal("a repo_id of %d bytes", len(where.GetRepoId()))
	case !directoryIdentifierValid(directoryIdentifierText, where.GetProject(), DirectoryProjectByteCount):
		return directoryRefusal("project of %d bytes or outside its class", len(where.GetProject()))
	case where.GetBranch() != "" && !directoryIdentifierValid(directoryIdentifierBranch, where.GetBranch(), DirectoryBranchByteCount):
		return directoryRefusal("branch of %d bytes or outside git's rule", len(where.GetBranch()))
	case where.GetPrivate() && (where.GetProject() != "" || where.GetBranch() != ""):
		return directoryRefusal("a private run naming its project or branch")
	case DirectoryClaimCount < len(item.GetClaims()):
		return directoryRefusal("%d claims", len(item.GetClaims()))
	}
	for index, claim := range item.GetClaims() {
		switch {
		case claim == nil, !directoryIdValid(claim.GetClaimId(), false):
			return directoryRefusal("claim %d's claim_id of %d bytes", index, len(claim.GetClaimId()))
		case !directoryProseValid(claim.GetText(), DirectoryClaimTextByteCount):
			return directoryRefusal("claim %d's text of %d bytes or outside its class", index, len(claim.GetText()))
		case DirectoryClaimTargetCount < len(claim.GetTargets()):
			return directoryRefusal("claim %d's %d targets", index, len(claim.GetTargets()))
		case claim.GetExpiresMillis() < 0 || item.GetExpiresMillis() < claim.GetExpiresMillis():
			return directoryRefusal("claim %d expiring past its run", index)
		}
		switch DirectoryClaimState(claim.GetState()) {
		case DirectoryClaimStateActive, DirectoryClaimStateReleased, DirectoryClaimStateHandedOff:
		default:
			return directoryRefusal("claim %d's state %d", index, claim.GetState())
		}
		for targetIndex, target := range claim.GetTargets() {
			if target == "" || !directoryIdentifierValid(directoryIdentifierText, target, DirectoryClaimTargetByteCount) {
				return directoryRefusal("claim %d's target %d of %d bytes or outside its class", index, targetIndex, len(target))
			}
		}
	}
	handoff := item.GetHandoff()
	switch {
	case !directoryIdValid(handoff.GetToMemberId(), true):
		return directoryRefusal("a to_member_id of %d bytes", len(handoff.GetToMemberId()))
	case handoff.GetToAgentLabel() != "" && !directoryIdentifierValid(directoryIdentifierLabel, handoff.GetToAgentLabel(), DirectoryLabelByteCount):
		return directoryRefusal("to_agent_label outside [a-z0-9-]{1,64}")
	case !directoryProseValid(handoff.GetNote(), DirectoryHandoffNoteByteCount):
		return directoryRefusal("handoff note of %d bytes or outside its class", len(handoff.GetNote()))
	case handoff.GetMillis() < 0:
		return directoryRefusal("handoff at %d", handoff.GetMillis())
	case state == DirectoryAnnouncementStateHandedOff && len(handoff.GetToMemberId()) == 0 && handoff.GetToAgentLabel() == "":
		return directoryRefusal("handed off to no member and no agent")
	}
	return nil
}

// A worker item's own fields.
func directoryCheckWorker(item *protocol.Announcement) error {
	who := item.GetWho()
	what := item.GetWhat()
	for index, tagId := range who.GetTagIds() {
		if !directoryIdValid(tagId, false) {
			return directoryRefusal("tag id %d of %d bytes", index, len(tagId))
		}
	}
	switch {
	case !directoryProseValid(what.GetDescription(), DirectoryDescriptionByteCount):
		return directoryRefusal("description of %d bytes or outside its class", len(what.GetDescription()))
	case DirectoryWorkerHarnessCount < len(what.GetHarnesses()):
		return directoryRefusal("%d harnesses", len(what.GetHarnesses()))
	case DirectoryWorkerAgentLabelCount < len(what.GetAgentLabels()):
		return directoryRefusal("%d agent labels", len(what.GetAgentLabels()))
	case DirectoryServiceCount < len(what.GetServices()):
		return directoryRefusal("%d services", len(what.GetServices()))
	case !directoryRequestsValid(what.GetRequests()):
		return directoryRefusal("requests %d", what.GetRequests())
	}
	for index, harness := range what.GetHarnesses() {
		if !directoryIdentifierValid(directoryIdentifierLabel, harness, DirectoryLabelByteCount) {
			return directoryRefusal("harness %d outside [a-z0-9-]{1,64}", index)
		}
	}
	for index, agentLabel := range what.GetAgentLabels() {
		if !directoryIdentifierValid(directoryIdentifierLabel, agentLabel, DirectoryLabelByteCount) {
			return directoryRefusal("agent label %d outside [a-z0-9-]{1,64}", index)
		}
	}
	for index, service := range what.GetServices() {
		kind := DirectoryServiceKind(service.GetKind())
		switch {
		case kind < DirectoryServiceKindSocket || DirectoryServiceKindBridgePort < kind:
			return directoryRefusal("service %d's kind %d", index, service.GetKind())
		case !directorySharedMarker(service.GetName()) && !directoryServiceNameValid(kind, service.GetName()):
			return directoryRefusal("service %d's name outside kind %d's grammar", index, service.GetKind())
		case !directoryProseValid(service.GetDescription(), DirectoryServiceDescriptionByteCount):
			return directoryRefusal("service %d's description of %d bytes or outside its class", index, len(service.GetDescription()))
		}
	}
	return nil
}

// A repo item's own fields: an announcement, or a private marker holding only who, repo_id, repo_kind and requests.
func directoryCheckRepo(item *protocol.Announcement) error {
	what := item.GetWhat()
	where := item.GetWhere()
	repoId, err := IdFromBytes(where.GetRepoId())
	if err != nil {
		return directoryRefusal("a repo_id of %d bytes", len(where.GetRepoId()))
	}
	if announcementId := DirectoryRepoAnnouncementId(repoId); !bytes.Equal(item.GetAnnouncementId(), announcementId[:]) {
		return directoryRefusal("an announcement_id not its repo's")
	}
	if where.GetPrivate() {
		if err := directoryItemOnlyFields(item, directoryPrivateMarkerFields); err != nil {
			return err
		}
	}
	switch protocol.RepoKind(what.GetRepoKind()) {
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_TEAM_RECORD,
		protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
	default:
		// config, mailcfg and the directory are never announced (§16.11's not default row)
		return directoryRefusal("repo_kind %d", what.GetRepoKind())
	}
	switch {
	case !directoryRequestsValid(what.GetRequests()):
		return directoryRefusal("requests %d", what.GetRequests())
	case !directoryProseValid(what.GetTitle(), DirectoryRepoTitleByteCount):
		return directoryRefusal("display name of %d bytes or outside its class", len(what.GetTitle()))
	case !directoryProseValid(what.GetDescription(), DirectoryDescriptionByteCount):
		return directoryRefusal("description of %d bytes or outside its class", len(what.GetDescription()))
	case DirectoryTopicCount < len(what.GetTopics()):
		return directoryRefusal("%d topics", len(what.GetTopics()))
	}
	for index, topic := range what.GetTopics() {
		if !directoryIdentifierValid(directoryIdentifierLabel, topic, DirectoryTopicByteCount) {
			return directoryRefusal("topic %d outside [a-z0-9-]{1,32}", index)
		}
	}
	roles := []uint32{}
	for _, role := range what.GetRoles() {
		if !DirectoryOfferedRoleAllowed(role) || slices.Contains(roles, role) {
			return directoryRefusal("role %d offered, or offered twice", role)
		}
		roles = append(roles, role)
	}
	return nil
}

// Whether AnnounceWhat.requests is open or closed, as a worker and a repo set it.
func directoryRequestsValid(requests uint32) bool {
	switch DirectoryRequests(requests) {
	case DirectoryRequestsOpen, DirectoryRequestsClosed:
		return true
	}
	return false
}

// Holds a request entry's body to §16.11's form and caps: request_id and subject at their lengths; exactly one
// target, tcp_ports only on a worker's, each a port once, at most a worker's services; a role its target takes
// (plan-RECORD-small-readings#4); a reason in the prose class within 512 B; filed_by a value, with an endorsement
// channel and its 32-byte hash exactly for an agent or a tagged sidecar, never harness in a tainted run (16.11's
// endorse row); an approval exactly for reach, whose approval_id is the request's; and a reach subject a sidecar, never
// a member, since a reach grant's subject is the spending sidecar. The approval's own bytes are DirectoryDecodeRequest's
// to check, as stored. Whether its target is open, its subject the filer's and its limits kept are the filer's and
// the readers' (RECORD-M6-18).
func DirectoryCheckRequest(request *protocol.DirectoryRequest) error {
	if request == nil {
		return directoryRefusal("no request")
	}
	targetKind, err := DirectoryRequestTargetKind(request.GetTarget())
	if err != nil {
		return err
	}
	ports := request.GetTarget().GetTcpPorts()
	if DirectoryRequestPortCount < len(ports) {
		return directoryRefusal("%d ports", len(ports))
	}
	for index, port := range ports {
		if port == 0 || 65535 < port || slices.Contains(ports[:index], port) {
			return directoryRefusal("port %d, or one twice", port)
		}
	}
	reach := targetKind == DirectoryTargetKindWorker || targetKind == DirectoryTargetKindSocket
	switch {
	case !directoryIdValid(request.GetRequestId(), false):
		return directoryRefusal("a request_id of %d bytes", len(request.GetRequestId()))
	case !directoryIdValid(request.GetSubject(), false):
		return directoryRefusal("a subject of %d bytes", len(request.GetSubject()))
	case reach && request.GetSubjectIsMember():
		return directoryRefusal("a reach request for a member")
	case !DirectoryRequestRoleAllowed(request.GetTarget(), request.GetRole()):
		return directoryRefusal("role %d for this target", request.GetRole())
	case request.GetGrantExpiresMillis() < 0 || request.GetNotAfterMillis() <= 0:
		return directoryRefusal("grant expiry %d and not_after %d", request.GetGrantExpiresMillis(), request.GetNotAfterMillis())
	case !directoryProseValid(request.GetReason(), DirectoryReasonByteCount):
		return directoryRefusal("reason of %d bytes or outside its class", len(request.GetReason()))
	case !directoryIdValid(request.GetAnnouncementId(), true):
		return directoryRefusal("an announcement_id of %d bytes", len(request.GetAnnouncementId()))
	}
	channel := protocol.ApprovalChannel(request.GetEndorsementChannel())
	switch DirectoryFiledBy(request.GetFiledBy()) {
	case DirectoryFiledByPerson:
		if channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED || len(request.GetEndorsementSha256()) != 0 {
			return directoryRefusal("an endorsement on a person's own request")
		}
	case DirectoryFiledByAgent, DirectoryFiledByTaggedSidecar:
		switch channel {
		case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
		case protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
			if request.GetTainted() {
				return directoryRefusal("a tainted run's request endorsed by harness evidence")
			}
		default:
			return directoryRefusal("endorsement channel %d", request.GetEndorsementChannel())
		}
		if len(request.GetEndorsementSha256()) != recordHashByteCount {
			return directoryRefusal("an endorsement_sha256 of %d bytes", len(request.GetEndorsementSha256()))
		}
	default:
		return directoryRefusal("filed_by %d", request.GetFiledBy())
	}
	approval := request.GetApproval()
	if reach != (approval != nil) {
		return directoryRefusal("an approval on a request for kind %d", targetKind)
	}
	if approval != nil && !bytes.Equal(approval.GetApprovalId(), request.GetRequestId()) {
		return directoryRefusal("an approval_id that is not the request's")
	}
	return nil
}

// Holds a decision entry's body to §16.11's form and caps, and answers the Signed ApprovalDecision an approved reach
// carries, parsed from its bytes as stored: request_id and request_entry_sha256 at their lengths; an outcome; an
// approval naming its subject and its statement's hash, and exactly one of a repo's log position and reach's
// ApprovalDecision, which approves this request on channel device or presence, never harness (16.11's decide row);
// a denial and a cancel naming no statement, subject or expiry; a note in the prose class within 512 B. Whether its
// decider was eligible and its statement is in the log are the requester's (RECORD-M6-19, RECORD-M6-20).
func DirectoryCheckDecision(decision *protocol.DirectoryDecision) error {
	_, err := directoryCheckDecision(decision)
	return err
}

// DirectoryCheckDecision's checks, answering an approved reach's ApprovalDecision as parsed from its bytes as stored,
// nil for any other decision.
func directoryCheckDecision(decision *protocol.DirectoryDecision) (*StoredApprovalDecision, error) {
	if decision == nil {
		return nil, directoryRefusal("no decision")
	}
	switch {
	case !directoryIdValid(decision.GetRequestId(), false):
		return nil, directoryRefusal("a request_id of %d bytes", len(decision.GetRequestId()))
	case len(decision.GetRequestEntrySha256()) != recordHashByteCount:
		return nil, directoryRefusal("a request_entry_sha256 of %d bytes", len(decision.GetRequestEntrySha256()))
	case decision.GetGrantExpiresMillis() < 0:
		return nil, directoryRefusal("grant expiry %d", decision.GetGrantExpiresMillis())
	case !directoryProseValid(decision.GetNote(), DirectoryDecisionNoteByteCount):
		return nil, directoryRefusal("note of %d bytes or outside its class", len(decision.GetNote()))
	}
	switch DirectoryOutcome(decision.GetOutcome()) {
	case DirectoryOutcomeApproved:
		switch {
		case len(decision.GetStatementSha256()) != recordHashByteCount:
			return nil, directoryRefusal("an approval's statement_sha256 of %d bytes", len(decision.GetStatementSha256()))
		case !directoryIdValid(decision.GetSubject(), false):
			return nil, directoryRefusal("an approval's subject of %d bytes", len(decision.GetSubject()))
		case (decision.GetStatementPosition() != 0) == (len(decision.GetApprovalDecision()) != 0):
			return nil, directoryRefusal("an approval naming both or neither of a log position and an approval decision")
		}
		if len(decision.GetApprovalDecision()) == 0 {
			return nil, nil
		}
		approvalDecision, err := ParseStoredApprovalDecision(decision.GetApprovalDecision())
		if err != nil {
			return nil, directoryRefusal("an approval decision that does not parse: %v", err)
		}
		switch {
		case protocol.ApprovalVerdict(approvalDecision.Decision.GetDecision()) != protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE:
			return nil, directoryRefusal("an approval carrying a denial")
		case protocol.ApprovalChannel(approvalDecision.Decision.GetChannel()) == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
			return nil, directoryRefusal("a reach approval on channel harness")
		case !bytes.Equal(approvalDecision.Decision.GetApprovalId(), decision.GetRequestId()):
			return nil, directoryRefusal("an approval decision for another request")
		}
		return approvalDecision, nil
	case DirectoryOutcomeDenied, DirectoryOutcomeCancelled:
		if len(decision.GetStatementSha256()) != 0 || decision.GetStatementPosition() != 0 || len(decision.GetApprovalDecision()) != 0 ||
			len(decision.GetSubject()) != 0 || decision.GetGrantExpiresMillis() != 0 {
			return nil, directoryRefusal("outcome %d naming a statement, subject or expiry", decision.GetOutcome())
		}
		return nil, nil
	}
	return nil, directoryRefusal("outcome %d", decision.GetOutcome())
}

// Holds a notice to §16.11's form and its 256 B: request_id and requester_sidecar_id at their lengths, the request
// entry's seq and the request's expiry set; pending with no outcome and at most the first approval of a rule asking
// two, or decided, approved with one or two approvals or denied naming its one denial; each DecisionRef's decider and
// header hash at their lengths and its seq set, no decider named twice. Whether those entries hold what the notice
// says is the requester's to read (16.11's receipt row).
func DirectoryCheckNotice(notice *protocol.DirectoryNotice) error {
	if notice == nil {
		return directoryRefusal("no notice")
	}
	if size := proto.Size(notice); DirectoryNoticeByteCount < size {
		return directoryRefusal("a notice of %d bytes", size)
	}
	switch {
	case !directoryIdValid(notice.GetRequestId(), false):
		return directoryRefusal("a request_id of %d bytes", len(notice.GetRequestId()))
	case !directoryIdValid(notice.GetRequesterSidecarId(), false):
		return directoryRefusal("a requester_sidecar_id of %d bytes", len(notice.GetRequesterSidecarId()))
	case notice.GetEntrySeq() == 0:
		return directoryRefusal("entry_seq 0")
	case notice.GetNotAfterMillis() <= 0:
		return directoryRefusal("not_after %d", notice.GetNotAfterMillis())
	}
	decisionCount := len(notice.GetDecisions())
	switch DirectoryNoticeState(notice.GetState()) {
	case DirectoryNoticeStatePending:
		if notice.GetOutcome() != 0 || 1 < decisionCount {
			return directoryRefusal("a pending notice with outcome %d and %d decisions", notice.GetOutcome(), decisionCount)
		}
	case DirectoryNoticeStateDecided:
		switch DirectoryOutcome(notice.GetOutcome()) {
		case DirectoryOutcomeApproved:
			if decisionCount < 1 || DirectoryNoticeDecisionCount < decisionCount {
				return directoryRefusal("an approved notice naming %d decisions", decisionCount)
			}
		case DirectoryOutcomeDenied:
			if decisionCount != 1 {
				return directoryRefusal("a denied notice naming %d decisions", decisionCount)
			}
		default:
			return directoryRefusal("a decided notice with outcome %d", notice.GetOutcome())
		}
	default:
		return directoryRefusal("notice state %d", notice.GetState())
	}
	deciderIds := [][]byte{}
	for index, decision := range notice.GetDecisions() {
		switch {
		case decision == nil, !directoryIdValid(decision.GetDeciderSidecarId(), false):
			return directoryRefusal("decision %d's decider of %d bytes", index, len(decision.GetDeciderSidecarId()))
		case decision.GetSeq() == 0:
			return directoryRefusal("decision %d at seq 0", index)
		case len(decision.GetHeaderSha256()) != recordHashByteCount:
			return directoryRefusal("decision %d's header_sha256 of %d bytes", index, len(decision.GetHeaderSha256()))
		case slices.ContainsFunc(deciderIds, func(deciderId []byte) bool { return bytes.Equal(deciderId, decision.GetDeciderSidecarId()) }):
			return directoryRefusal("decision %d's decider named twice", index)
		}
		deciderIds = append(deciderIds, decision.GetDeciderSidecarId())
	}
	return nil
}

// Holds an erasure request entry's body to its form: request_id and repo_id at their lengths, and the private
// marker's version it lapses with set. Whether its signer may ask is the erasure runner's (RECORD-M6-21).
func DirectoryCheckErasureRequest(request *protocol.DirectoryErasureRequest) error {
	switch {
	case request == nil:
		return directoryRefusal("no erasure request")
	case !directoryIdValid(request.GetRequestId(), false):
		return directoryRefusal("a request_id of %d bytes", len(request.GetRequestId()))
	case !directoryIdValid(request.GetRepoId(), false):
		return directoryRefusal("a repo_id of %d bytes", len(request.GetRepoId()))
	case request.GetMarkerVersion() == 0:
		return directoryRefusal("marker_version 0")
	}
	return nil
}
