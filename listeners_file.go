//go:build !ios_extension && !sidecar_http

// The listeners file (DESIGN-COMPUTE §26.6; LSTN-M13-01): a device's list as it publishes it, the versionless
// s/<sidecar_id> in its network's listeners repo, and the bytes the live ask answers as `file` (§26.8). Its fields are
// protocol/listeners.proto's, written as JSON (compute-plan-lstn-file-fields, QD-1249):
//
//	{"v":1,"sidecar":"<id>","updated":"2026-11-23T14:05Z","withheld":null,"truncated":false,"entries":[
//	 {"kind":"socket","proto":"tcp","port":5432,"bind":"0.0.0.0","desc":"postgres","desc_by":"program"}, ...]}
//
// keys in the field numbers' order, which is §26.6's example's, an empty field left out but withheld and truncated
// always written; enum values as their names' words after the enum's prefix, lowercase, an audience's words joined by
// a dash as `ur bridge public-tls` takes them; times in UTC to the minute. MarshalListenersFile writes the entries in
// the order it is given them, which BuildListenersList makes §26.5's (maps, forwards, tls, ssh and sock entries, then
// sockets by port), so the bytes are a function of the list, and §26.6's own example, a socket first, reads back as it
// is written.
//
// The file carries no address of its host, ever: readers take the host's overlay address and name from the config
// (§26.4). An entry's bind is "0.0.0.0" or "::"; an own-view entry, which names its address, is never in a file, and
// the writer refuses to write one, as the parser refuses to read one.
//
// ParseListenersFile refuses, naming the field and never its value (I-13): bytes past FileMaxByteCount; another v; a
// sidecar that is not its path's; an unknown kind, proto, desc_by, withheld or audience; more than EntryMaxCount
// entries; a withheld file with entries; a port of 0 where the kind has one; a field past FieldMaxByteCount; and a
// description past DescriptionMaxCharCount characters or one that cleaning would change: a control or format character,
// a run of the untrusted-data markers' words in any case and spacing, or text not in NFKC (R-LSTN-8). The markers'
// words are the root's own constants (harness_untrusted.go), since the root may not import mcp. A writer cleans every
// description before it lists it (ListenersCleanDescription), and MarshalListenersFile holds a file to the same checks,
// so a device never writes what its readers refuse. Unknown keys are ignored, so a later writer may add a field.
//
// Safe for concurrent use: nothing here holds state.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/urnetwork/sidecar/protocol"
)

// The file's format version (§26.6's v).
const ListenersFileVersion = 1

// The listeners repo's directory of device files, s/<sidecar_id> (§26.6).
const listenersFilePathPrefix = "s/"

// A file's times: UTC to the minute, as §26.6's example writes them.
const listenersFileTimeLayout = "2006-01-02T15:04Z"

// The binds a file may name: every IPv4 interface, or "::" (which takes IPv4 too, or on Windows may: v4_uncertain).
const (
	listenersBindAnyIpv4 = "0.0.0.0"
	listenersBindAnyIpv6 = "::"
)

// The fixed descriptions §26.4 gives an owner the OS does not name, and ssh's.
const (
	ListenersDescriptionOtherUser = "another user's program"
	ListenersDescriptionSystem    = "a system program"
	ListenersDescriptionSsh       = "ssh (ur ssh-server)"
)

// A file a reader refuses, or a writer refuses to write.
var ErrListenersFileInvalid = errors.New("listeners file refused")

// The words of an enum value as the file writes it: after the enum's prefix, lowercase, an audience's joined by a dash.
var (
	listenersKindWords = map[protocol.ListenersEntryKind]string{
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET:  "socket",
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP:     "map",
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD: "forward",
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCK:    "sock",
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS:     "tls",
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SSH:     "ssh",
	}
	listenersProtocolWords = map[protocol.ListenersProtocol]string{
		protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP: "tcp",
		protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP: "udp",
	}
	listenersSourceWords = map[protocol.ListenersDescriptionSource]string{
		protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_LABEL:          "label",
		protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_PROGRAM:        "program",
		protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_OTHER_USER:     "other_user",
		protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_SYSTEM:         "system",
		protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET_PROGRAM: "target_program",
		protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET:         "target",
		protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_FIXED:          "fixed",
	}
	listenersWithheldWords = map[protocol.ListenersWithheld]string{
		protocol.ListenersWithheld_LISTENERS_WITHHELD_DISCLOSURE:  "disclosure",
		protocol.ListenersWithheld_LISTENERS_WITHHELD_DEVICE:      "device",
		protocol.ListenersWithheld_LISTENERS_WITHHELD_NETWORK_ACK: "network_ack",
		protocol.ListenersWithheld_LISTENERS_WITHHELD_HIDDEN:      "hidden",
		protocol.ListenersWithheld_LISTENERS_WITHHELD_NETWORK:     "network",
	}
	listenersAudienceWords = map[protocol.AclAudience]string{
		protocol.AclAudience_ACL_AUDIENCE_MEMBERS:        "members",
		protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE: "members-device",
		protocol.AclAudience_ACL_AUDIENCE_LINK:           "link",
		protocol.AclAudience_ACL_AUDIENCE_PUBLIC:         "public",
	}
)

// A run of either untrusted-data marker's words, in any case, with anything but a letter or a digit between them:
// built from the root's constants, so the listeners' check and the Harness's fences name one marker.
var listenersMarkerPattern = func() *regexp.Regexp {
	alternatives := []string{}
	for _, marker := range []string{HarnessUntrustedBegin, HarnessUntrustedEnd} {
		words := []string{}
		for _, word := range strings.Fields(marker) {
			words = append(words, regexp.QuoteMeta(word))
		}
		alternatives = append(alternatives, strings.Join(words, `[^\p{L}\p{N}]*`))
	}
	return regexp.MustCompile(`(?i)(?:` + strings.Join(alternatives, `|`) + `)`)
}()

// The JSON a file is, its keys in the field numbers' order (the file's comment).
type listenersFileJson struct {
	V         uint32                `json:"v"`
	Sidecar   string                `json:"sidecar"`
	Updated   string                `json:"updated"`
	Withheld  *string               `json:"withheld"`
	Truncated bool                  `json:"truncated"`
	Entries   []*listenersEntryJson `json:"entries"`
}

// One entry's JSON. own_view has no key: an own-view entry is never in a file.
type listenersEntryJson struct {
	Kind        string `json:"kind"`
	Proto       string `json:"proto"`
	Port        uint32 `json:"port,omitempty"`
	Bind        string `json:"bind,omitempty"`
	Target      string `json:"target,omitempty"`
	To          string `json:"to,omitempty"`
	Desc        string `json:"desc,omitempty"`
	DescBy      string `json:"desc_by,omitempty"`
	Until       string `json:"until,omitempty"`
	Shared      bool   `json:"shared,omitempty"`
	V4Uncertain bool   `json:"v4_uncertain,omitempty"`
	Name        string `json:"name,omitempty"`
	Audience    string `json:"audience,omitempty"`
	Shadowed    bool   `json:"shadowed,omitempty"`
}

// The path of a device's file in its network's listeners repo.
func ListenersFilePath(sidecarId Id) string {
	return listenersFilePathPrefix + sidecarId.String()
}

// A refusal naming what failed and never a value.
func listenersFileRefusal(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrListenersFileInvalid}, args...)...)
}

// The value whose words in words are word, and whether there is one.
func listenersWordValue[T comparable](words map[T]string, word string) (T, bool) {
	for value, held := range words {
		if held == word {
			return value, true
		}
	}
	var zero T
	return zero, false
}

// A time of the file, ms since the epoch, as the file writes it: UTC to the minute.
func listenersFileTimeText(ms int64) string {
	return time.UnixMilli(ms).UTC().Truncate(time.Minute).Format(listenersFileTimeLayout)
}

// A file's time read back, ms since the epoch: exactly as listenersFileTimeText writes one, from 1970 to 9999.
func listenersFileTime(text string) (int64, bool) {
	parsed, err := time.Parse(listenersFileTimeLayout, text)
	if err != nil || parsed.Format(listenersFileTimeLayout) != text || parsed.UnixMilli() <= 0 {
		return 0, false
	}
	return parsed.UnixMilli(), true
}

// Whether a time ms since the epoch is one the file can write: after 1970 and before 10000.
func listenersFileTimeValid(ms int64) bool {
	return 0 < ms && time.UnixMilli(ms).UTC().Year() < 10000
}

// Whether character is one no description holds: a C0 or C1 control; a format character, which holds the bidi
// controls, the zero-width characters, U+FEFF and the tag characters; a variation selector or another default-ignorable
// code point; or a line or paragraph separator. Each acts on the text around it or shows nothing to a person while a
// model still reads it.
func listenersDescriptionCharacterRefused(character rune) bool {
	return unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
		unicode.Is(unicode.Variation_Selector, character) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, character) ||
		unicode.In(character, unicode.Zl, unicode.Zp) || character == utf8.RuneError
}

// text with each run of whitespace one space, every refused character dropped, trimmed.
func listenersDescriptionSpaced(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	space := false
	for _, character := range text {
		switch {
		case unicode.IsSpace(character):
			space = builder.Len() != 0
		case listenersDescriptionCharacterRefused(character):
		default:
			if space {
				builder.WriteByte(' ')
				space = false
			}
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

// text as a description (§26.5's caps, R-LSTN-8): every control and format character and every other refused
// character dropped and each run of whitespace one space; in NFKC, so a compatibility form of a marker's letters reads
// as the letters, and spaced again, since NFKC makes spaces of some characters; every run of the untrusted-data
// markers' words removed, until none is left; cut to maxCharCount characters, trimmed. A writer lists only what this
// gives, and a reader refuses a description it would change (the file's comment), so cleaning again changes nothing.
func ListenersCleanDescription(text string, maxCharCount int) string {
	if maxCharCount <= 0 {
		return ""
	}
	// after the first pass text only shrinks or holds: what a pass drops can join a letter and its mark, which NFKC then
	// composes, and nothing a pass adds is dropped again, so a few passes settle any text
	for {
		cleaned := listenersDescriptionSpaced(norm.NFKC.String(listenersDescriptionSpaced(text)))
		for {
			removed := listenersMarkerPattern.ReplaceAllString(cleaned, " ")
			if removed == cleaned {
				break
			}
			cleaned = listenersDescriptionSpaced(removed)
		}
		if maxCharCount < utf8.RuneCountInString(cleaned) {
			runes := []rune(cleaned)
			cleaned = strings.TrimSpace(string(runes[:maxCharCount]))
		}
		if cleaned == text {
			return cleaned
		}
		text = cleaned
	}
}

// Whether text is a description a reader takes: valid UTF-8, at most maxCharCount characters, and one cleaning leaves
// as it is.
func listenersDescriptionValid(text string, maxCharCount int) bool {
	return utf8.ValidString(text) && utf8.RuneCountInString(text) <= maxCharCount &&
		ListenersCleanDescription(text, maxCharCount) == text
}

// Whether text is a name, a forward's to or a target as a file holds it: non-empty valid UTF-8 of at most maxByteCount
// bytes with no space and no refused character.
func listenersFieldValid(text string, maxByteCount int) bool {
	if text == "" || maxByteCount < len(text) || !utf8.ValidString(text) {
		return false
	}
	for _, character := range text {
		if unicode.IsSpace(character) || listenersDescriptionCharacterRefused(character) {
			return false
		}
	}
	return true
}

// Whether target is an ip:port with a port, IPv6 bracketed, written as netip writes it.
func listenersTargetValid(target string, maxByteCount int) bool {
	if maxByteCount < len(target) {
		return false
	}
	addrPort, err := netip.ParseAddrPort(target)
	return err == nil && addrPort.Port() != 0 && addrPort.String() == target
}

// A file entry's checks, which a writer's and a reader's share: index names it in a refusal.
func listenersFileEntryCheck(index int, entry *protocol.ListenersEntry, settings *ListenersSettings) error {
	if entry == nil {
		return listenersFileRefusal("entry %d is empty", index)
	}
	kind := entry.GetKind()
	if _, ok := listenersKindWords[kind]; !ok {
		return listenersFileRefusal("entry %d's kind is not one the file knows", index)
	}
	if _, ok := listenersProtocolWords[entry.GetProto()]; !ok {
		return listenersFileRefusal("entry %d's proto is not one the file knows", index)
	}
	if entry.GetOwnView() != protocol.ListenersOwnView_LISTENERS_OWN_VIEW_UNSPECIFIED {
		return listenersFileRefusal("entry %d is an own-view entry", index)
	}
	port := entry.GetPort()
	switch {
	case kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCK:
		if port != 0 {
			return listenersFileRefusal("entry %d, a socket name, has a port", index)
		}
	case port == 0 || 65535 < port:
		return listenersFileRefusal("entry %d's port is not 1 to 65535", index)
	}

	bind := entry.GetBind()
	switch kind {
	case protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET:
		if bind != listenersBindAnyIpv4 && bind != listenersBindAnyIpv6 {
			return listenersFileRefusal("entry %d, a socket, binds no wildcard", index)
		}
	case protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD:
		if bind != "" && bind != listenersBindAnyIpv4 && bind != listenersBindAnyIpv6 {
			return listenersFileRefusal("entry %d, a forward, binds an address", index)
		}
	default:
		if bind != "" {
			return listenersFileRefusal("entry %d's kind binds nothing", index)
		}
	}
	isSocket := kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET
	if entry.GetV4Uncertain() && (!isSocket || bind != listenersBindAnyIpv6) {
		return listenersFileRefusal("entry %d is v4_uncertain and no socket on ::", index)
	}
	if (entry.GetShared() || entry.GetShadowed()) && !isSocket {
		return listenersFileRefusal("entry %d is shared or shadowed and no socket", index)
	}

	// a map always has its target; a tls or sock entry has one where a local address takes its connections, and none
	// where the host's own process does, an app's listener
	isMap := kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP
	mayTarget := isMap || kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS ||
		kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCK
	switch target := entry.GetTarget(); {
	case !mayTarget && target != "":
		return listenersFileRefusal("entry %d's kind has no target", index)
	case isMap && target == "":
		return listenersFileRefusal("entry %d, a map, has no target", index)
	case target != "" && !listenersTargetValid(target, settings.FieldMaxByteCount):
		return listenersFileRefusal("entry %d's target is no ip:port", index)
	}
	isForward := kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD
	switch {
	case isForward && !listenersFieldValid(entry.GetTo(), settings.FieldMaxByteCount):
		return listenersFileRefusal("entry %d's to is not a destination", index)
	case !isForward && entry.GetTo() != "":
		return listenersFileRefusal("entry %d's kind has no to", index)
	}
	hasName := kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCK ||
		kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS
	switch {
	case hasName && !listenersFieldValid(entry.GetName(), settings.FieldMaxByteCount):
		return listenersFileRefusal("entry %d's name is not a name", index)
	case !hasName && entry.GetName() != "":
		return listenersFileRefusal("entry %d's kind has no name", index)
	}
	isTls := kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS
	_, knownAudience := listenersAudienceWords[entry.GetAudience()]
	switch {
	case isTls && !knownAudience:
		return listenersFileRefusal("entry %d's audience is not one the file knows", index)
	case !isTls && entry.GetAudience() != protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED:
		return listenersFileRefusal("entry %d's kind has no audience", index)
	}

	desc := entry.GetDesc()
	descBy := entry.GetDescBy()
	_, knownSource := listenersSourceWords[descBy]
	switch {
	case desc == "" && descBy == protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_UNSPECIFIED:
	case desc == "" || !knownSource:
		return listenersFileRefusal("entry %d's desc and desc_by do not come together", index)
	case !listenersDescriptionValid(desc, settings.DescriptionMaxCharCount):
		return listenersFileRefusal("entry %d's desc is past its cap or holds what cleaning removes", index)
	}

	hasEnd := kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP ||
		kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD || isTls
	switch until := entry.GetUntil(); {
	case until == 0:
	case !hasEnd:
		return listenersFileRefusal("entry %d's kind has no end", index)
	case !listenersFileTimeValid(until):
		return listenersFileRefusal("entry %d's until is not a time the file writes", index)
	}
	return nil
}

// What keys an entry once in a file: two entries of one kind, protocol, port and name are one too many.
type listenersFileEntryKey struct {
	kind  protocol.ListenersEntryKind
	proto protocol.ListenersProtocol
	port  uint32
	name  string
}

// A file's checks, which a writer's and a reader's share: the file's comment's refusals but the byte count and the
// path, which only bytes and a reader have.
func listenersFileCheck(file *protocol.ListenersFile, settings *ListenersSettings) error {
	if file == nil {
		return listenersFileRefusal("no file")
	}
	if file.GetV() != ListenersFileVersion {
		return listenersFileRefusal("v is not %d", ListenersFileVersion)
	}
	if _, err := IdFromBytes(file.GetSidecar()); err != nil {
		return listenersFileRefusal("sidecar is no id")
	}
	if !listenersFileTimeValid(file.GetUpdated()) {
		return listenersFileRefusal("updated is not a time the file writes")
	}
	withheld := file.GetWithheld()
	if _, ok := listenersWithheldWords[withheld]; !ok && withheld != protocol.ListenersWithheld_LISTENERS_WITHHELD_UNSPECIFIED {
		return listenersFileRefusal("withheld is not one the file knows")
	}
	entries := file.GetEntries()
	if withheld != protocol.ListenersWithheld_LISTENERS_WITHHELD_UNSPECIFIED && (len(entries) != 0 || file.GetTruncated()) {
		return listenersFileRefusal("a withheld file lists entries")
	}
	if settings.EntryMaxCount < len(entries) {
		return listenersFileRefusal("more than %d entries", settings.EntryMaxCount)
	}
	keys := map[listenersFileEntryKey]bool{}
	for index, entry := range entries {
		if err := listenersFileEntryCheck(index, entry, settings); err != nil {
			return err
		}
		key := listenersFileEntryKey{kind: entry.GetKind(), proto: entry.GetProto(), port: entry.GetPort(), name: entry.GetName()}
		if keys[key] {
			return listenersFileRefusal("entry %d repeats an entry", index)
		}
		keys[key] = true
	}
	return nil
}

// The file's bytes as §26.6 writes it (the file's comment), after the checks a reader makes, so a device never writes
// what its readers refuse.
func MarshalListenersFile(file *protocol.ListenersFile, settings *ListenersSettings) ([]byte, error) {
	if err := listenersFileCheck(file, settings); err != nil {
		return nil, err
	}
	sidecarId, _ := IdFromBytes(file.GetSidecar())
	encoded := &listenersFileJson{
		V:         file.GetV(),
		Sidecar:   sidecarId.String(),
		Updated:   listenersFileTimeText(file.GetUpdated()),
		Truncated: file.GetTruncated(),
		Entries:   make([]*listenersEntryJson, 0, len(file.GetEntries())),
	}
	if withheld := file.GetWithheld(); withheld != protocol.ListenersWithheld_LISTENERS_WITHHELD_UNSPECIFIED {
		word := listenersWithheldWords[withheld]
		encoded.Withheld = &word
	}
	for _, entry := range file.GetEntries() {
		entryJson := &listenersEntryJson{
			Kind:        listenersKindWords[entry.GetKind()],
			Proto:       listenersProtocolWords[entry.GetProto()],
			Port:        entry.GetPort(),
			Bind:        entry.GetBind(),
			Target:      entry.GetTarget(),
			To:          entry.GetTo(),
			Desc:        entry.GetDesc(),
			DescBy:      listenersSourceWords[entry.GetDescBy()],
			Shared:      entry.GetShared(),
			V4Uncertain: entry.GetV4Uncertain(),
			Name:        entry.GetName(),
			Audience:    listenersAudienceWords[entry.GetAudience()],
			Shadowed:    entry.GetShadowed(),
		}
		if until := entry.GetUntil(); until != 0 {
			entryJson.Until = listenersFileTimeText(until)
		}
		encoded.Entries = append(encoded.Entries, entryJson)
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	// a description's & and < stay as they are, which a reader reads the same either way
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(encoded); err != nil {
		return nil, listenersFileRefusal("the file does not encode")
	}
	data := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	if settings.FileMaxByteCount < len(data) {
		return nil, listenersFileRefusal("past %d bytes", settings.FileMaxByteCount)
	}
	return data, nil
}

// The file at s/<sidecarId> as its readers take it (the file's comment), or ErrListenersFileInvalid. Its times are the
// minutes the file writes; nothing in it decides anything but what a viewer shows and the listed set its badges read.
func ParseListenersFile(data []byte, sidecarId Id, settings *ListenersSettings) (*protocol.ListenersFile, error) {
	if settings.FileMaxByteCount < len(data) {
		return nil, listenersFileRefusal("past %d bytes", settings.FileMaxByteCount)
	}
	decoded := &listenersFileJson{}
	if err := json.Unmarshal(data, decoded); err != nil {
		return nil, listenersFileRefusal("not the file's JSON")
	}
	if decoded.V != ListenersFileVersion {
		return nil, listenersFileRefusal("v is not %d", ListenersFileVersion)
	}
	writer, err := ParseId(decoded.Sidecar)
	if err != nil || writer.String() != decoded.Sidecar {
		return nil, listenersFileRefusal("sidecar is no id")
	}
	if writer != sidecarId {
		return nil, listenersFileRefusal("sidecar is not its path's")
	}
	updated, ok := listenersFileTime(decoded.Updated)
	if !ok {
		return nil, listenersFileRefusal("updated is not a time the file writes")
	}
	file := &protocol.ListenersFile{
		V:         decoded.V,
		Sidecar:   writer.Bytes(),
		Updated:   updated,
		Truncated: decoded.Truncated,
		Entries:   []*protocol.ListenersEntry{},
	}
	if decoded.Withheld != nil {
		withheld, ok := listenersWordValue(listenersWithheldWords, *decoded.Withheld)
		if !ok {
			return nil, listenersFileRefusal("withheld is not one the file knows")
		}
		file.Withheld = withheld
	}
	if settings.EntryMaxCount < len(decoded.Entries) {
		return nil, listenersFileRefusal("more than %d entries", settings.EntryMaxCount)
	}
	for index, entryJson := range decoded.Entries {
		if entryJson == nil {
			return nil, listenersFileRefusal("entry %d is empty", index)
		}
		entry := &protocol.ListenersEntry{
			Port:        entryJson.Port,
			Bind:        entryJson.Bind,
			Target:      entryJson.Target,
			To:          entryJson.To,
			Desc:        entryJson.Desc,
			Shared:      entryJson.Shared,
			V4Uncertain: entryJson.V4Uncertain,
			Name:        entryJson.Name,
			Shadowed:    entryJson.Shadowed,
		}
		if entry.Kind, ok = listenersWordValue(listenersKindWords, entryJson.Kind); !ok {
			return nil, listenersFileRefusal("entry %d's kind is not one the file knows", index)
		}
		if entry.Proto, ok = listenersWordValue(listenersProtocolWords, entryJson.Proto); !ok {
			return nil, listenersFileRefusal("entry %d's proto is not one the file knows", index)
		}
		if entryJson.DescBy != "" {
			if entry.DescBy, ok = listenersWordValue(listenersSourceWords, entryJson.DescBy); !ok {
				return nil, listenersFileRefusal("entry %d's desc_by is not one the file knows", index)
			}
		}
		if entryJson.Audience != "" {
			if entry.Audience, ok = listenersWordValue(listenersAudienceWords, entryJson.Audience); !ok {
				return nil, listenersFileRefusal("entry %d's audience is not one the file knows", index)
			}
		}
		if entryJson.Until != "" {
			if entry.Until, ok = listenersFileTime(entryJson.Until); !ok {
				return nil, listenersFileRefusal("entry %d's until is not a time the file writes", index)
			}
		}
		file.Entries = append(file.Entries, entry)
	}
	if err := listenersFileCheck(file, settings); err != nil {
		return nil, err
	}
	return file, nil
}
