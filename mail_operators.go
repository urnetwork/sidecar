// Owner decision 135's operator list (D-MAIL-13; R-MAIL-16, I-11; MAIL-M7-10): mail_operators.yml in this public
// repository, embedded in each release with its list version. The root links no YAML parser, so mail_operators_gen.go
// holds the list as Go, written from the file by go generate, and TestMailOperatorsGenIsCurrent fails while the two
// differ (plan-MAIL-small-readings#18). ParseMailOperatorList reads the file's one shape, so anyone can recheck a
// label against a list version with no new server or key.
//
// The shape, and nothing else:
//
//	version: <n>                a positive integer, raised with every change to the list
//	operators:                  one item an operator, or "operators: []" for none
//	  - id: <id>                1 to 64 bytes of a-z, 0-9 and inner dashes, unique: MailTlsBasis.operator_id
//	    name: <text>            how a person sees it named, 1 to 128 bytes
//	    ptr_suffixes: [<name>]  names its sending addresses' forward-confirmed PTR names end with, at a label
//	    dkim_domains: [<name>]  organizational domains its DKIM signatures' d= fall at or under
//	    dane: <url>             where it publishes its outbound DANE enforcement, absent where it publishes none
//	    mta_sts: <url>          where it publishes its outbound MTA-STS enforcement, likewise
//
// A line is blank, a comment starting with #, or one of those, indented as shown; a value is a plain or
// double-quoted scalar, a list a flow list on its line. An operator names at least one PTR suffix or DKIM domain and
// publishes DANE or MTA-STS enforcement, since the list is of DANE- or MTA-STS-enforcing operators; a name is
// lowercase LDH labels, two or more, at most 253 bytes; a source is an https URL. A list entry is an
// operator-reputation inference, never proof of a path, so a name may not claim end-to-end delivery.
//
// No connect, go-smtp or mox: on every leg. Safe for concurrent use; a list is never changed once made.

//go:generate env SIDECAR_REGENERATE_MAIL_OPERATORS=1 go test -run ^TestMailOperatorsGenIsCurrent$ .

package sidecar

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The bounds of an operator's id and name, and of a source's URL. Format values.
const (
	mailOperatorIdMaxByteCount     = 64
	mailOperatorNameMaxByteCount   = 128
	mailOperatorSourceMaxByteCount = 512
)

// A list that breaks mail_operators.yml's shape or rules. Wrapped with the line and what broke.
var ErrMailOperatorListInvalid = errors.New("mail operator list invalid")

// One operator on the list.
type MailOperator struct {
	// The entry's id, which MailTlsBasis.operator_id holds.
	Id string
	// How a person sees it named.
	Name string
	// Names its sending addresses' forward-confirmed PTR names end with, at a label.
	PtrSuffixes []string
	// Organizational domains its DKIM signatures' d= fall at or under.
	DkimDomains []string
	// Where it publishes its outbound DANE enforcement, or empty where it publishes none.
	DaneSource string
	// Where it publishes its outbound MTA-STS enforcement, or empty where it publishes none.
	MtaStsSource string
}

// A version of the list.
type MailOperatorList struct {
	// Raised with every change, and kept in each label's basis.
	Version uint32
	// In the file's order, which is the order a label takes the first match in.
	Operators []*MailOperator
}

// A copy, so a caller's changes reach no other holder.
func (self *MailOperator) clone() *MailOperator {
	copied := *self
	copied.PtrSuffixes = slices.Clone(self.PtrSuffixes)
	copied.DkimDomains = slices.Clone(self.DkimDomains)
	return &copied
}

// A copy, so a caller's changes reach no other holder.
func (self *MailOperatorList) clone() *MailOperatorList {
	list := &MailOperatorList{Version: self.Version, Operators: make([]*MailOperator, 0, len(self.Operators))}
	for _, operator := range self.Operators {
		list.Operators = append(list.Operators, operator.clone())
	}
	return list
}

// The operator with id, or nil.
func (self *MailOperatorList) Operator(id string) *MailOperator {
	for _, operator := range self.Operators {
		if operator.Id == id {
			return operator
		}
	}
	return nil
}

// The list this release embeds, from mail_operators.yml, as a copy.
func MailOperatorListEmbedded() *MailOperatorList {
	return mailOperatorListEmbedded.clone()
}

// A value of the shape: a scalar or a flow list.
type mailYamlValue struct {
	scalar string
	list   []string
	isList bool
}

// One list item: its keys in order, each to its value.
type mailYamlItem struct {
	keys   []string
	values map[string]mailYamlValue
	// The line the item starts on, for errors.
	line int
}

// A file of the shape: its top-level scalars and lists, and the lines each starts on.
type mailYamlDocument struct {
	scalars map[string]string
	lists   map[string][]*mailYamlItem
	lines   map[string]int
}

// An error at line.
func mailYamlError(line int, format string, arguments ...any) error {
	return fmt.Errorf("%w: line %d: %s", ErrMailOperatorListInvalid, line, fmt.Sprintf(format, arguments...))
}

// Whether key is a key of the shape: lowercase letters and underscores.
func mailYamlKey(key string) bool {
	if key == "" {
		return false
	}
	for index := range len(key) {
		if (key[index] < 'a' || 'z' < key[index]) && key[index] != '_' {
			return false
		}
	}
	return true
}

// A scalar's text: plain, which no space ends or starts and no # or quote opens, or double-quoted with \" and \\ its
// only escapes.
func mailYamlScalar(text string, line int) (string, error) {
	if strings.HasPrefix(text, `"`) {
		if len(text) < 2 || !strings.HasSuffix(text, `"`) {
			return "", mailYamlError(line, "an unclosed quote")
		}
		var builder strings.Builder
		inner := text[1 : len(text)-1]
		for index := 0; index < len(inner); index += 1 {
			c := inner[index]
			switch {
			case c == '\\' && index+1 < len(inner) && (inner[index+1] == '"' || inner[index+1] == '\\'):
				builder.WriteByte(inner[index+1])
				index += 1
			case c == '\\' || c == '"':
				return "", mailYamlError(line, "an escape the shape does not have")
			default:
				builder.WriteByte(c)
			}
		}
		return builder.String(), nil
	}
	if text == "" || text != strings.TrimSpace(text) || strings.ContainsAny(text[:1], `#'[]{}&*!|>%@`+"`") ||
		strings.Contains(text, " #") || strings.Contains(text, ": ") {
		return "", mailYamlError(line, "a plain scalar the shape does not take")
	}
	return text, nil
}

// A value: a flow list [a, b], or a scalar.
func mailYamlParseValue(text string, line int) (mailYamlValue, error) {
	if !strings.HasPrefix(text, "[") {
		scalar, err := mailYamlScalar(text, line)
		return mailYamlValue{scalar: scalar}, err
	}
	if !strings.HasSuffix(text, "]") {
		return mailYamlValue{}, mailYamlError(line, "an unclosed list")
	}
	value := mailYamlValue{isList: true, list: []string{}}
	inner := strings.TrimSpace(text[1 : len(text)-1])
	if inner == "" {
		return value, nil
	}
	for element := range strings.SplitSeq(inner, ",") {
		scalar, err := mailYamlScalar(strings.TrimSpace(element), line)
		if err != nil {
			return mailYamlValue{}, err
		}
		value.list = append(value.list, scalar)
	}
	return value, nil
}

// "key: value", or "key:" with nothing after it, which opens a list of items.
func mailYamlKeyValue(text string, line int) (string, string, error) {
	key, value, found := strings.Cut(text, ":")
	if !found || !mailYamlKey(key) {
		return "", "", mailYamlError(line, "no key")
	}
	if value != "" && !strings.HasPrefix(value, " ") {
		return "", "", mailYamlError(line, "no space after the colon")
	}
	return key, strings.TrimSpace(value), nil
}

// The shape's document: top-level scalars, lists of items opened by "key:" or empty as "key: []", items at two
// spaces each "- key: value", their further keys at four. Anything else, a repeated key included, is an error.
func parseMailYamlSubset(text string) (*mailYamlDocument, error) {
	document := &mailYamlDocument{scalars: map[string]string{}, lists: map[string][]*mailYamlItem{}, lines: map[string]int{}}
	// the list items now go to, and the item being read
	openList := ""
	var item *mailYamlItem
	addToItem := func(text string, line int) error {
		key, value, err := mailYamlKeyValue(text, line)
		if err != nil {
			return err
		}
		if _, ok := item.values[key]; ok {
			return mailYamlError(line, "%s repeated", key)
		}
		parsed, err := mailYamlParseValue(value, line)
		if err != nil {
			return err
		}
		item.keys = append(item.keys, key)
		item.values[key] = parsed
		return nil
	}
	for index, rawLine := range strings.Split(text, "\n") {
		line := index + 1
		trimmed := strings.TrimRight(rawLine, " \t\r")
		if strings.TrimSpace(trimmed) == "" || strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			continue
		}
		if strings.ContainsRune(trimmed, '\t') {
			return nil, mailYamlError(line, "a tab")
		}
		switch {
		case !strings.HasPrefix(trimmed, " "):
			key, value, err := mailYamlKeyValue(trimmed, line)
			if err != nil {
				return nil, err
			}
			if _, ok := document.lines[key]; ok {
				return nil, mailYamlError(line, "%s repeated", key)
			}
			document.lines[key] = line
			openList, item = "", nil
			switch value {
			case "":
				openList = key
				document.lists[key] = []*mailYamlItem{}
			case "[]":
				document.lists[key] = []*mailYamlItem{}
			default:
				scalar, err := mailYamlScalar(value, line)
				if err != nil {
					return nil, err
				}
				document.scalars[key] = scalar
			}
		case strings.HasPrefix(trimmed, "  - "):
			if openList == "" {
				return nil, mailYamlError(line, "an item outside a list")
			}
			item = &mailYamlItem{values: map[string]mailYamlValue{}, line: line}
			document.lists[openList] = append(document.lists[openList], item)
			if err := addToItem(strings.TrimPrefix(trimmed, "  - "), line); err != nil {
				return nil, err
			}
		case strings.HasPrefix(trimmed, "    ") && !strings.HasPrefix(trimmed, "     "):
			if item == nil {
				return nil, mailYamlError(line, "a key outside an item")
			}
			if err := addToItem(strings.TrimPrefix(trimmed, "    "), line); err != nil {
				return nil, err
			}
		default:
			return nil, mailYamlError(line, "an indent the shape does not have")
		}
	}
	return document, nil
}

// Whether name is a lowercase LDH name of two or more labels, at most 253 bytes.
func mailOperatorName(name string) bool {
	if dnsDomainMaxByteCount < len(name) {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !isDnsLowerLdhLabel(label) {
			return false
		}
	}
	return true
}

// Whether source is an https URL within its bound.
func mailOperatorSource(source string) bool {
	if source == "" || mailOperatorSourceMaxByteCount < len(source) {
		return false
	}
	parsed, err := url.Parse(source)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

// The list a document's version and operators give, held to the file header's rules.
func mailOperatorListOf(document *mailYamlDocument) (*MailOperatorList, error) {
	versionText, ok := document.scalars["version"]
	if !ok {
		return nil, mailYamlError(0, "no version")
	}
	version, err := strconv.ParseUint(versionText, 10, 32)
	if err != nil || version == 0 || strings.TrimLeft(versionText, "0123456789") != "" {
		return nil, mailYamlError(document.lines["version"], "a version that is no positive integer")
	}
	items, ok := document.lists["operators"]
	if !ok {
		return nil, mailYamlError(0, "no operators")
	}
	list := &MailOperatorList{Version: uint32(version), Operators: []*MailOperator{}}
	for _, item := range items {
		operator := &MailOperator{PtrSuffixes: []string{}, DkimDomains: []string{}}
		for _, key := range item.keys {
			value := item.values[key]
			wantList := key == "ptr_suffixes" || key == "dkim_domains"
			if value.isList != wantList {
				return nil, mailYamlError(item.line, "%s takes the wrong kind of value", key)
			}
			switch key {
			case "id":
				operator.Id = value.scalar
			case "name":
				operator.Name = value.scalar
			case "ptr_suffixes":
				operator.PtrSuffixes = value.list
			case "dkim_domains":
				operator.DkimDomains = value.list
			case "dane":
				operator.DaneSource = value.scalar
			case "mta_sts":
				operator.MtaStsSource = value.scalar
			default:
				return nil, mailYamlError(item.line, "an operator has no %s", key)
			}
		}
		if err := mailOperatorCheck(operator, list); err != nil {
			return nil, mailYamlError(item.line, "%v", err)
		}
		list.Operators = append(list.Operators, operator)
	}
	return list, nil
}

// The file header's rules for one operator joining list.
func mailOperatorCheck(operator *MailOperator, list *MailOperatorList) error {
	id := operator.Id
	if id == "" || mailOperatorIdMaxByteCount < len(id) || id[0] == '-' || id[len(id)-1] == '-' || !isDnsLowerBytes(id, "-") {
		return errors.New("an id outside the rule")
	}
	if list.Operator(id) != nil {
		return errors.New("an id repeated")
	}
	name := operator.Name
	if name == "" || mailOperatorNameMaxByteCount < len(name) || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
		return errors.New("a name outside the rule")
	}
	folded := strings.ToLower(name)
	if strings.Contains(folded, "end-to-end") || strings.Contains(folded, "end to end") {
		return errors.New("a name claiming end-to-end delivery")
	}
	for _, suffix := range append(slices.Clone(operator.PtrSuffixes), operator.DkimDomains...) {
		if !mailOperatorName(suffix) {
			return errors.New("a name that is no lowercase domain of two labels or more")
		}
	}
	if len(operator.PtrSuffixes) == 0 && len(operator.DkimDomains) == 0 {
		return errors.New("neither a PTR suffix nor a DKIM domain")
	}
	if operator.DaneSource == "" && operator.MtaStsSource == "" {
		return errors.New("no published enforcement")
	}
	for _, source := range []string{operator.DaneSource, operator.MtaStsSource} {
		if source != "" && !mailOperatorSource(source) {
			return errors.New("a source that is no https URL")
		}
	}
	return nil
}

// A list in mail_operators.yml's shape, held to its rules: ErrMailOperatorListInvalid with the line otherwise.
func ParseMailOperatorList(text string) (*MailOperatorList, error) {
	document, err := parseMailYamlSubset(text)
	if err != nil {
		return nil, err
	}
	for key, line := range document.lines {
		if key != "version" && key != "operators" {
			return nil, mailYamlError(line, "a list has no %s", key)
		}
	}
	return mailOperatorListOf(document)
}

// Whether name is suffix or ends with it at a label.
func mailNameUnder(name string, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}
