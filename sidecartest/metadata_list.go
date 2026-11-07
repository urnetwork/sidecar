// §2.8's list as code reads it (I-18, D-TRUST-4): metadata_list.yml at the top of the repository, which
// make metadata copies byte for byte from §2.8 and check/ holds to it, so a row changes only through
// the design.
//
// The reader is strict because §22.7 makes every parse error fail the build. yaml.v3 refuses a
// duplicate key and, with KnownFields, a field no row has; what it would let through is refused here
// too: a second document, a tab, an alias, a value YAML reads as anything but a string, and a live row
// without its service, store, sees, why, ttl or owner. Rows use why where §22.7 says purpose. A failure
// on the real list means §2.8 regressed, which is a question for the design, never a setting to
// loosen here.
//
// Values are safe for concurrent use once built.

package sidecartest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Where make metadata writes the list, from the top of the repository.
const metadataListFileName = "metadata_list.yml"

// The sibling directory a consumer's go.mod replace points at, which is where a test in server finds
// the list.
const metadataListSiblingName = "sidecar"

// What a MetadataFamily names.
type MetadataFamilyKind string

const (
	// A Redis key family, tag then suffix: {evsq_}, {acl_}e, {dns}serial:.
	MetadataFamilyRedis MetadataFamilyKind = "redis"
	// An object key family, by its first path element: place/, gkm/.
	MetadataFamilyObject MetadataFamilyKind = "object"
	// A Postgres table, as a store names it: network_client_lease.
	MetadataFamilyTable MetadataFamilyKind = "table"
	// A column or stored value a row names in snake_case: helo_name, acl_subject_client_id.
	MetadataFamilyColumn MetadataFamilyKind = "column"
)

// One thing a row names, in the form a guard compares: a Redis or object family reads as §22.7 writes
// it, with the row's <id> placeholders gone, so {acl_<networkId>}e is {acl_}e.
type MetadataFamily struct {
	Kind MetadataFamilyKind
	Name string
}

// One row of the list. A live row has every field but Withdrawn, and a withdrawn row, which keeps its
// id so citations resolve, has only Withdrawn.
type MetadataRow struct {
	// Its key, such as evs-3.
	Id string `yaml:"-"`
	// The file's line its key is on.
	Line int `yaml:"-"`

	Service string `yaml:"service"`
	// Prose naming tables, Redis families, object families, logs or memory. Families reads it.
	Store string `yaml:"store"`
	Sees  string `yaml:"sees"`
	// §22.7's purpose.
	Why string `yaml:"why"`
	Ttl string `yaml:"ttl"`
	// The section that designs the value and states its ttl.
	Owner string `yaml:"owner"`
	// Why the row left the list.
	Withdrawn string `yaml:"withdrawn"`
}

// True for a row that still names values a server sees.
func (self *MetadataRow) Live() bool {
	return self.Withdrawn == ""
}

// Every parsed list, in file order.
type MetadataList struct {
	// From the file's first line, such as v8. Empty if that line names none.
	Version string
	// Every row, withdrawn ones included, in file order.
	Rows []*MetadataRow

	rowIdRows map[string]*MetadataRow
}

// A row by id, or nil.
func (self *MetadataList) Row(rowId string) *MetadataRow {
	return self.rowIdRows[rowId]
}

// The rows that still name values, in file order.
func (self *MetadataList) LiveRows() []*MetadataRow {
	liveRows := []*MetadataRow{}
	for _, row := range self.Rows {
		if row.Live() {
			liveRows = append(liveRows, row)
		}
	}
	return liveRows
}

// The withdrawn rows, in file order.
func (self *MetadataList) WithdrawnRows() []*MetadataRow {
	withdrawnRows := []*MetadataRow{}
	for _, row := range self.Rows {
		if !row.Live() {
			withdrawnRows = append(withdrawnRows, row)
		}
	}
	return withdrawnRows
}

// The live rows that name a family, in file order, so a guard can walk from a value to its rows.
func (self *MetadataList) RowsNaming(family MetadataFamily) []*MetadataRow {
	rows := []*MetadataRow{}
	for _, row := range self.LiveRows() {
		if slices.Contains(row.Families(), family) {
			rows = append(rows, row)
		}
	}
	return rows
}

// The list's own id form: a service word, then a number.
var metadataRowIdPattern = regexp.MustCompile(`^[a-z]+-[0-9]+$`)

// The first line's version.
var metadataVersionPattern = regexp.MustCompile(`^# metadata_list\.yml (v[0-9]+)\b`)

// Reads the repository's list, looking from the working directory up. A test's working directory is
// its package's: in this repository the list is in an ancestor, and in a consumer that replaces this
// module it is in the sidecar sibling of an ancestor, the same directory go.mod's relative replace
// names. Finding none is an error, so a guard run from elsewhere fails rather than checks nothing.
func LoadMetadataList() (*MetadataList, error) {
	listPath, err := findMetadataList()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(listPath)
	if err != nil {
		return nil, err
	}
	list, err := ParseMetadataList(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", listPath, err)
	}
	return list, nil
}

// The nearest list above the working directory.
func findMetadataList() (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for directory := workingDirectory; ; directory = filepath.Dir(directory) {
		for _, listPath := range []string{
			filepath.Join(directory, metadataListFileName),
			filepath.Join(directory, metadataListSiblingName, metadataListFileName),
		} {
			if _, err := os.Stat(listPath); err == nil {
				return listPath, nil
			}
		}
		if directory == filepath.Dir(directory) {
			return "", fmt.Errorf("no %s above %s", metadataListFileName, workingDirectory)
		}
	}
}

// Parses the list's bytes. Any error means the build fails (§22.7).
func ParseMetadataList(data []byte) (*MetadataList, error) {
	// a tab inside a plain value is legal YAML, and no row has one: two parsers disagree on the rest
	if index := bytes.IndexByte(data, '\t'); 0 <= index {
		return nil, fmt.Errorf("line %d holds a tab", 1+bytes.Count(data[:index], []byte("\n")))
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	rowIdRows := map[string]*MetadataRow{}
	if err := decoder.Decode(&rowIdRows); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the list holds no rows")
		}
		return nil, err
	}
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("the list holds a second document: %v", err)
	}

	document := &yaml.Node{}
	if err := yaml.Unmarshal(data, document); err != nil {
		return nil, err
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("line %d: the list is no mapping of rows", root.Line)
	}

	list := &MetadataList{rowIdRows: rowIdRows}
	if match := metadataVersionPattern.FindSubmatch(data); match != nil {
		list.Version = string(match[1])
	}
	findings := []error{}
	for index := 0; index < len(root.Content); index += 2 {
		keyNode := root.Content[index]
		valueNode := root.Content[index+1]
		if err := metadataRowNodeError(keyNode, valueNode); err != nil {
			findings = append(findings, err)
			continue
		}
		row := rowIdRows[keyNode.Value]
		row.Id = keyNode.Value
		row.Line = keyNode.Line
		list.Rows = append(list.Rows, row)
		findings = append(findings, row.fieldErrors()...)
	}
	if err := errors.Join(findings...); err != nil {
		return nil, err
	}
	return list, nil
}

// True when a node says plainly what it holds, so every parser reads the same text.
func metadataNodeIsPlainString(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!str" && node.Anchor == ""
}

// What is wrong with a row's shape: its id, and each key and value being a plain string.
func metadataRowNodeError(keyNode *yaml.Node, valueNode *yaml.Node) error {
	if !metadataNodeIsPlainString(keyNode) || !metadataRowIdPattern.MatchString(keyNode.Value) {
		return fmt.Errorf("line %d: %q is no row id", keyNode.Line, keyNode.Value)
	}
	if valueNode.Kind != yaml.MappingNode || valueNode.Anchor != "" {
		return fmt.Errorf("line %d: %s is no plain mapping", valueNode.Line, keyNode.Value)
	}
	findings := []error{}
	for index := 0; index < len(valueNode.Content); index += 2 {
		fieldKeyNode := valueNode.Content[index]
		fieldValueNode := valueNode.Content[index+1]
		if !metadataNodeIsPlainString(fieldKeyNode) {
			findings = append(findings, fmt.Errorf("line %d: %s has the key %q", fieldKeyNode.Line, keyNode.Value, fieldKeyNode.Value))
		}
		if !metadataNodeIsPlainString(fieldValueNode) {
			findings = append(findings, fmt.Errorf("line %d: %s's %s is no plain string", fieldValueNode.Line, keyNode.Value, fieldKeyNode.Value))
		}
	}
	return errors.Join(findings...)
}

// What a live or withdrawn row lacks or must not carry.
func (self *MetadataRow) fieldErrors() []error {
	fieldValues := []struct {
		name  string
		value string
	}{
		{name: "service", value: self.Service},
		{name: "store", value: self.Store},
		{name: "sees", value: self.Sees},
		{name: "why", value: self.Why},
		{name: "ttl", value: self.Ttl},
		{name: "owner", value: self.Owner},
	}
	findings := []error{}
	for _, field := range fieldValues {
		blank := strings.TrimSpace(field.value) == ""
		if self.Live() && blank {
			findings = append(findings, fmt.Errorf("line %d: live row %s has no %s", self.Line, self.Id, field.name))
		}
		if !self.Live() && !blank {
			findings = append(findings, fmt.Errorf("line %d: withdrawn row %s still has %s", self.Line, self.Id, field.name))
		}
	}
	return findings
}

// A Redis family in a store: a tag, its opening word and what follows the tag in the key. A suffix ends
// at a colon, which is where {dns}serial:<root>'s variable part starts.
var metadataRedisPattern = regexp.MustCompile(`\{([a-z]+_?)[^}]*\}([a-z]*:?)`)

// connect-4's form: a tag, then the three keys under it, each with its kind.
var metadataRedisSuffixListPattern = regexp.MustCompile(`\{([a-z]+_)[^}]*\} ([a-z]+) \([^)]*\), ([a-z]+) \([^)]*\) and ([a-z]+) \([^)]*\)`)

// sock-1's form: a tag, and a further key named by its suffix alone.
var metadataRedisNamedSuffixPattern = regexp.MustCompile(`\{([a-z]+_)[^}]*\}.*\(suffix ([a-z]+)\)`)

// An object key or family at a word's start, whatever follows its first path element.
var metadataObjectPattern = regexp.MustCompile(`(?:^|[\s,;])([a-z]+/)`)

// Anything key-shaped, which the snake_case search must not read inside: <repo_id> is a placeholder.
var metadataKeyTokenPattern = regexp.MustCompile(`\{[^}]*\}\S*|\S*/\S*|<[^>]*>`)

// table.column.
var metadataQualifiedColumnPattern = regexp.MustCompile(`\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\.([a-z][a-z0-9_]*)\b`)

// A snake_case word.
var metadataSnakePattern = regexp.MustCompile(`\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b`)

// A store with what its parentheses hold split out: the main text, which names the row's own stores,
// and the commentary, which names columns and, as gkm-7's does for gen/, things that are no family of
// their own. A parenthesis inside a tag, as in {mxc_<HMAC_k(prefix)>}, is the key's.
func metadataSplitStore(store string) (string, string) {
	var body strings.Builder
	var commentary strings.Builder
	depth := 0
	inTag := false
	for _, character := range store {
		switch {
		case character == '{' && depth == 0:
			inTag = true
		case character == '}':
			inTag = false
		case character == '(' && !inTag:
			depth += 1
			commentary.WriteRune(' ')
			continue
		case character == ')' && !inTag && 0 < depth:
			depth -= 1
			continue
		}
		if 0 < depth {
			commentary.WriteRune(character)
		} else {
			body.WriteRune(character)
		}
	}
	return body.String(), commentary.String()
}

// What the row's store and sees name, each once, Redis families first, then objects, tables and
// columns, each in the order written. store is prose, so TestMetadataListNamesSection22sFamilies
// holds this against every family §22.7 lists, or a guard would pass by reading nothing.
func (self *MetadataRow) Families() []MetadataFamily {
	families := []MetadataFamily{}
	add := func(kind MetadataFamilyKind, name string) {
		family := MetadataFamily{Kind: kind, Name: name}
		if !slices.Contains(families, family) {
			families = append(families, family)
		}
	}
	if !self.Live() {
		return families
	}
	body, commentary := metadataSplitStore(self.Store)

	listedTags := map[string]bool{}
	for _, match := range metadataRedisSuffixListPattern.FindAllStringSubmatch(self.Store, -1) {
		listedTags[match[1]] = true
		for _, suffix := range match[2:] {
			add(MetadataFamilyRedis, "{"+match[1]+"}"+suffix)
		}
	}
	for _, match := range metadataRedisPattern.FindAllStringSubmatch(body, -1) {
		if match[2] != "" || !listedTags[match[1]] {
			add(MetadataFamilyRedis, "{"+match[1]+"}"+match[2])
		}
	}
	for _, match := range metadataRedisNamedSuffixPattern.FindAllStringSubmatch(self.Store, -1) {
		add(MetadataFamilyRedis, "{"+match[1]+"}"+match[2])
	}

	for _, match := range metadataObjectPattern.FindAllStringSubmatch(body, -1) {
		add(MetadataFamilyObject, match[1])
	}

	bodyWords := metadataKeyTokenPattern.ReplaceAllString(body, " ")
	for _, match := range metadataQualifiedColumnPattern.FindAllStringSubmatch(bodyWords, -1) {
		add(MetadataFamilyTable, match[1])
		add(MetadataFamilyColumn, match[2])
	}
	bodyWords = metadataQualifiedColumnPattern.ReplaceAllString(bodyWords, " ")
	for _, word := range metadataSnakePattern.FindAllString(bodyWords, -1) {
		// evs-2's store names a value, the ref_id inside its keys
		if strings.HasSuffix(word, "_id") {
			add(MetadataFamilyColumn, word)
		} else {
			add(MetadataFamilyTable, word)
		}
	}
	for _, text := range []string{commentary, self.Sees} {
		for _, word := range metadataSnakePattern.FindAllString(metadataKeyTokenPattern.ReplaceAllString(text, " "), -1) {
			add(MetadataFamilyColumn, word)
		}
	}
	slices.SortStableFunc(families, func(a MetadataFamily, b MetadataFamily) int {
		return metadataFamilyKindOrder(a.Kind) - metadataFamilyKindOrder(b.Kind)
	})
	return families
}

// Where a kind sorts in Families.
func metadataFamilyKindOrder(kind MetadataFamilyKind) int {
	return slices.Index([]MetadataFamilyKind{
		MetadataFamilyRedis,
		MetadataFamilyObject,
		MetadataFamilyTable,
		MetadataFamilyColumn,
	}, kind)
}
