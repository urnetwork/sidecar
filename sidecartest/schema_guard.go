// §22.7's schema guard (I-18), sidecar's half: every proto field, object key family and Redis key
// family a server sees maps to a row of §2.8's list, and each live row maps back, or says when it will.
// A value the list lacks fails the build, which is what makes a row the precondition of a value. Its
// other half, Postgres columns, is server's TestSidecarSchemaGuard (TEST-M1-03).
//
// What it reads:
//
//   - metadata_list.yml, by the strict reader in metadata_list.go.
//   - The map: testdata/metadata/fields.yml, which has the sections of schemaGuardMapFile, and every
//     testdata/**/metadata_rows.yml, an area's own lines for the fields it adds, one schemaGuardAreaField
//     each. Every file is read as strictly as the list, and a field sits in one file only. A message an
//     area's file names is a root, since a file says that of a message by mapping its fields.
//   - What is true of the tree: the registered descriptors (schema_guard_proto.go) and the key
//     literals of the engine packages (schema_guard_keys.go).
//   - After a scenario, what the stores hold, through CheckStores.
//
// Where a row exists only in prose no scanner parses, the map still names the value: nothing here is a
// skip list. A value §2.8 does not name yet sits in the open section beside the question that asks for
// its row, reported on every run and failing from the milestone the question must be settled by.
//
// A guard is immutable once built, and safe for concurrent use.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/urnetwork/sidecar"
)

// The map's two forms, from the top of the repository.
const (
	schemaGuardFieldsPath = "testdata/metadata/fields.yml"
	schemaGuardTestdata   = "testdata"
	// An area's own file, anywhere under testdata.
	schemaGuardAreaFileName = "metadata_rows.yml"
)

// How many keys one List page asks for.
const schemaGuardListPageCount = 1000

// A row whose values are not all in the tree yet, or whose way back is Postgres.
type schemaGuardRowEntry struct {
	// The milestone whose exit brings its first value, Mn. A row nothing backs carries this until then.
	Planned string `yaml:"planned"`
	// Tables and families its store names whose code is in server, so its half holds them. This is the
	// way back for a row with nothing here.
	Server []string `yaml:"server"`
}

// A value in the tree that §2.8 does not name yet, which a question asks to add.
type schemaGuardOpenEntry struct {
	// The row the question proposes.
	Row string `yaml:"row"`
	// The file under .stack/questions.
	Question string `yaml:"question"`
	// The milestone whose exit it must be settled by, Mn. From then on it fails.
	Until string `yaml:"until"`
}

// The sections of fields.yml. Keys of a field are Message.field, and names are the message's in its
// package.
type schemaGuardMapFile struct {
	// The newest milestone whose exit has passed, Mn, which each gate's sweep raises.
	Landed string `yaml:"landed"`
	// The milestone whose exit a pending line in an area's file must be settled by, Mn, if it names
	// none of its own.
	PendingUntil string `yaml:"pending_until"`
	// Messages a server decodes or builds, each with who and where the design says so.
	Roots map[string]string `yaml:"roots"`
	// Sealed bytes on a message a server reads, each with the message it opens to. The field itself
	// shows as ciphertext, so it still needs a row, but what it opens to does not.
	Seals map[string]string `yaml:"seals"`
	// Messages no root reaches and no seal names, each with why no server reads it.
	SealedMessages map[string]string `yaml:"sealed_messages"`
	// Files whose every message nothing reaches is sealed, each with why.
	SealedFiles map[string]string `yaml:"sealed_files"`
	// Every reached field, each with its row.
	Fields map[string]string `yaml:"fields"`
	// Reached fields that stay empty on whatever a server reads, each with the rule that says so.
	Unset map[string]string `yaml:"unset"`
	// Reached fields no row names yet.
	Open map[string]*schemaGuardOpenEntry `yaml:"open"`
	// Enum.VALUE, each with its row: values of a flag or kind a row names. A mapped enum is mapped whole.
	EnumValues map[string]string `yaml:"enum_values"`
	// A value only a row's prose names, in those words, each with its row.
	Values map[string]string `yaml:"values"`
	// Live rows that need saying more about, by id.
	Rows map[string]*schemaGuardRowEntry `yaml:"rows"`
	// Literals that read as a key and are none, each with what they are.
	NotKeys map[string]string `yaml:"not_keys"`
	// Globs from the top of the repository that hold key builders, besides the engine packages.
	KeySources []string `yaml:"key_sources"`
}

// One line of a metadata_rows.yml, keyed Message.field: the row that shows the field, and either the
// row's own words for it or why it says none yet.
type schemaGuardAreaField struct {
	// The field's number and its type as a .proto writes it, repeated included, for a message no design
	// fence pins. Absent: not checked.
	Number int32  `yaml:"number"`
	Type   string `yaml:"type"`
	Row    string `yaml:"row"`
	// Words of the row, so a row that stops saying them fails.
	Sees string `yaml:"sees"`
	// Why the row does not name the field yet, for a question to settle.
	Pending string `yaml:"pending"`
	// The milestone whose exit that must happen by, Mn, or else the map's pending_until.
	Until string `yaml:"until"`
}

// What a guard reads, so a test can plant a tree of its own.
type SchemaGuardSources struct {
	// The top of the repository: metadata_list.yml, testdata/ and the engine packages.
	RootDirectory string
	// The descriptors to walk.
	Files *protoregistry.Files
}

// What CheckStores reads.
type SchemaGuardStores struct {
	// Every metadata cluster and the segment cluster are listed whole. nil: none to read.
	Blobs sidecar.BlobStore
	// Every Redis key: a FakeRedis's Dump, or what SCAN finds on real stores.
	RedisKeys []string
}

// §22.7's guard over one tree.
type SchemaGuard struct {
	sources *SchemaGuardSources
	list    *MetadataList
	// fields.yml with the areas' fields, each in its section
	fieldMap *schemaGuardMapFile
	// the lines those came from, by Message.field, with their files
	areaFields map[string]*schemaGuardAreaField
	// the milestone number fieldMap.Landed names
	landedMilestone int
	// object and Redis families some live row names, by name
	familyRows map[MetadataFamily][]string
}

// The milestone number in Mn.
var schemaGuardMilestonePattern = regexp.MustCompile(`^M([0-9]+)$`)

// The number in a milestone, or an error naming what was read.
func schemaGuardMilestone(text string) (int, error) {
	match := schemaGuardMilestonePattern.FindStringSubmatch(text)
	if match == nil {
		return 0, fmt.Errorf("%q is no milestone", text)
	}
	return strconv.Atoi(match[1])
}

// The guard over this repository, with the descriptors its protocol packages register, found as
// LoadMetadataList finds the list.
func LoadSchemaGuard() (*SchemaGuard, error) {
	listPath, err := findMetadataList()
	if err != nil {
		return nil, err
	}
	return NewSchemaGuard(&SchemaGuardSources{
		RootDirectory: filepath.Dir(listPath),
		Files:         protoregistry.GlobalFiles,
	})
}

// A guard over sources, or an error if the list or the map does not read.
func NewSchemaGuard(sources *SchemaGuardSources) (*SchemaGuard, error) {
	list, err := readMetadataList(filepath.Join(sources.RootDirectory, metadataListFileName))
	if err != nil {
		return nil, err
	}
	fieldMap, areaFields, err := readSchemaGuardMap(sources.RootDirectory)
	if err != nil {
		return nil, err
	}
	landedMilestone, err := schemaGuardMilestone(fieldMap.Landed)
	if err != nil {
		return nil, fmt.Errorf("%s: landed: %w", schemaGuardFieldsPath, err)
	}
	familyRows := map[MetadataFamily][]string{}
	for _, row := range list.LiveRows() {
		for _, family := range row.Families() {
			familyRows[family] = append(familyRows[family], row.Id)
		}
	}
	return &SchemaGuard{
		sources:         sources,
		list:            list,
		fieldMap:        fieldMap,
		areaFields:      areaFields,
		landedMilestone: landedMilestone,
		familyRows:      familyRows,
	}, nil
}

// fields.yml, then every metadata_rows.yml under testdata, as one map, with the area lines it took.
func readSchemaGuardMap(rootDirectory string) (*schemaGuardMapFile, map[string]*schemaGuardAreaField, error) {
	data, err := os.ReadFile(filepath.Join(rootDirectory, schemaGuardFieldsPath))
	if err != nil {
		return nil, nil, err
	}
	fieldMap := &schemaGuardMapFile{
		Roots:  map[string]string{},
		Fields: map[string]string{},
		Open:   map[string]*schemaGuardOpenEntry{},
	}
	if _, err := decodeStrictYaml(data, fieldMap); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", schemaGuardFieldsPath, err)
	}
	areaFields := map[string]*schemaGuardAreaField{}
	err = filepath.WalkDir(filepath.Join(rootDirectory, schemaGuardTestdata), func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != schemaGuardAreaFileName {
			return nil
		}
		relativePath, err := filepath.Rel(rootDirectory, walkPath)
		if err != nil {
			return err
		}
		return fieldMap.readAreaFile(walkPath, relativePath, areaFields)
	})
	if err != nil {
		return nil, nil, err
	}
	return fieldMap, areaFields, nil
}

// Folds one area's file in, refusing a field the map already holds: two homes for one value would let
// them disagree.
func (self *schemaGuardMapFile) readAreaFile(areaPath string, relativePath string, areaFields map[string]*schemaGuardAreaField) error {
	data, err := os.ReadFile(areaPath)
	if err != nil {
		return err
	}
	fileFields := map[string]*schemaGuardAreaField{}
	if _, err := decodeStrictYaml(data, &fileFields); err != nil {
		return fmt.Errorf("%s: %w", relativePath, err)
	}
	for _, key := range slices.Sorted(maps.Keys(fileFields)) {
		field := fileFields[key]
		_, inFields := self.Fields[key]
		_, inOpen := self.Open[key]
		if inFields || inOpen {
			return fmt.Errorf("%s: %s is mapped twice", relativePath, key)
		}
		if (field.Sees == "") == (field.Pending == "") {
			return fmt.Errorf("%s: %s needs exactly one of sees and pending", relativePath, key)
		}
		messageName, _, found := schemaGuardCutField(key)
		if !found {
			return fmt.Errorf("%s: %s is not Message.field", relativePath, key)
		}
		if _, listed := self.Roots[messageName]; !listed {
			self.Roots[messageName] = "named by " + relativePath
		}
		areaFields[key] = field
		if field.Sees != "" {
			self.Fields[key] = field.Row
			continue
		}
		until := field.Until
		if until == "" {
			until = self.PendingUntil
		}
		self.Open[key] = &schemaGuardOpenEntry{Row: field.Row, Question: relativePath, Until: until}
	}
	return nil
}

// A Message.field key's two parts.
func schemaGuardCutField(key string) (string, string, bool) {
	separator := strings.LastIndexByte(key, '.')
	if separator < 0 {
		return "", "", false
	}
	return key[:separator], key[separator+1:], true
}

// Everything the guard can tell from the tree, each finding naming the value, sorted. Empty is the
// pass.
func (self *SchemaGuard) Check() ([]string, error) {
	literals, err := self.keyLiterals()
	if err != nil {
		return nil, err
	}
	findings := self.protoFindings()
	findings = append(findings, self.mapRowFindings()...)
	findings = append(findings, self.keyLiteralFindings(literals)...)
	findings = append(findings, self.rowFindings(literals)...)
	slices.Sort(findings)
	return slices.Compact(findings), nil
}

// What a row's id says about it as the target of a map entry, or "" for a live row.
func (self *SchemaGuard) rowTargetProblem(rowId string) string {
	row := self.list.Row(rowId)
	switch {
	case row == nil:
		return fmt.Sprintf("row %s, which metadata_list.yml does not hold", rowId)
	case !row.Live():
		return fmt.Sprintf("row %s, which is withdrawn", rowId)
	}
	return ""
}

// Each entry that names no live row, and each open entry past its milestone.
func (self *SchemaGuard) mapRowFindings() []string {
	findings := []string{}
	check := func(what string, targets map[string]string) {
		for key, rowId := range targets {
			if problem := self.rowTargetProblem(rowId); problem != "" {
				findings = append(findings, fmt.Sprintf("%s %s maps to %s", what, key, problem))
			}
		}
	}
	check("proto field", self.fieldMap.Fields)
	check("enum value", self.fieldMap.EnumValues)
	check("value", self.fieldMap.Values)
	for key, field := range self.areaFields {
		row := self.list.Row(field.Row)
		if row != nil && field.Sees != "" && !strings.Contains(row.Sees, field.Sees) {
			findings = append(findings, fmt.Sprintf("proto field %s quotes %q, and row %s no longer says that", key, field.Sees, row.Id))
		}
	}
	for key, entry := range self.fieldMap.Open {
		if problem := self.rowTargetProblem(entry.Row); problem != "" {
			findings = append(findings, fmt.Sprintf("open field %s proposes %s", key, problem))
		}
		if entry.Question == "" {
			findings = append(findings, fmt.Sprintf("open field %s names no question", key))
		}
		until, err := schemaGuardMilestone(entry.Until)
		switch {
		case err != nil:
			findings = append(findings, fmt.Sprintf("open field %s: until: %v", key, err))
		case until <= self.landedMilestone:
			findings = append(findings, fmt.Sprintf("open field %s: %s has landed and %s is still open: §2.8 must name it (I-18)", key, entry.Until, entry.Question))
		}
	}
	return findings
}

// What backs each live row now, by row id: every column, family or field that maps to it. An open
// field backs nothing, since §2.8 does not name it yet.
func (self *SchemaGuard) rowBackings(literals []*schemaGuardKeyLiteral) map[string][]string {
	backings := map[string][]string{}
	for field, rowId := range self.fieldMap.Fields {
		backings[rowId] = append(backings[rowId], field)
	}
	for enumValue, rowId := range self.fieldMap.EnumValues {
		backings[rowId] = append(backings[rowId], enumValue)
	}
	for value, rowId := range self.fieldMap.Values {
		backings[rowId] = append(backings[rowId], value)
	}
	for rowId, entry := range self.fieldMap.Rows {
		backings[rowId] = append(backings[rowId], entry.Server...)
	}
	for _, literal := range literals {
		for _, rowId := range self.literalRows(literal) {
			backings[rowId] = append(backings[rowId], literal.family.Name)
		}
	}
	return backings
}

// The way back: every live row has something behind it or a milestone still ahead, and the rows
// section says nothing false.
func (self *SchemaGuard) rowFindings(literals []*schemaGuardKeyLiteral) []string {
	findings := []string{}
	backings := self.rowBackings(literals)
	for rowId, entry := range self.fieldMap.Rows {
		row := self.list.Row(rowId)
		if problem := self.rowTargetProblem(rowId); problem != "" {
			findings = append(findings, fmt.Sprintf("the rows section names %s", problem))
			continue
		}
		for _, name := range entry.Server {
			if !slices.ContainsFunc(row.Families(), func(family MetadataFamily) bool { return family.Name == name }) {
				findings = append(findings, fmt.Sprintf("row %s says server's %s backs it, and its store does not name that", rowId, name))
			}
		}
		if entry.Planned == "" {
			continue
		}
		planned, err := schemaGuardMilestone(entry.Planned)
		if err != nil {
			findings = append(findings, fmt.Sprintf("row %s: planned: %v", rowId, err))
		} else if planned <= self.landedMilestone && len(backings[rowId]) == 0 {
			findings = append(findings, fmt.Sprintf("row %s: planned: %s, and %s has landed with nothing behind the row: map a column, family or field to it", rowId, entry.Planned, self.fieldMap.Landed))
		}
	}
	for _, row := range self.list.LiveRows() {
		entry := self.fieldMap.Rows[row.Id]
		if len(backings[row.Id]) == 0 && (entry == nil || entry.Planned == "") {
			findings = append(findings, fmt.Sprintf("row %s: nothing backs it: no column, family or field maps to it, and it carries no planned milestone", row.Id))
		}
	}
	return findings
}

// What a passing run leaned on, for the end of make check's output: the list's size, and what is
// planned or open rather than settled.
func (self *SchemaGuard) Reports() ([]string, error) {
	literals, err := self.keyLiterals()
	if err != nil {
		return nil, err
	}
	reports := []string{fmt.Sprintf(
		"metadata_list.yml %s: %d rows, %d live, %d withdrawn; %d proto fields mapped, %d never set on what a server reads, %d key literals read",
		self.list.Version, len(self.list.Rows), len(self.list.LiveRows()), len(self.list.WithdrawnRows()),
		len(self.fieldMap.Fields), len(self.fieldMap.Unset), len(literals),
	)}

	questionFields := map[string][]string{}
	for field, entry := range self.fieldMap.Open {
		key := fmt.Sprintf("%s, by %s's exit", entry.Question, entry.Until)
		questionFields[key] = append(questionFields[key], field)
	}
	for _, key := range slices.Sorted(maps.Keys(questionFields)) {
		fields := questionFields[key]
		slices.Sort(fields)
		reports = append(reports, fmt.Sprintf("%d proto fields no row names yet wait on %s: %s", len(fields), key, strings.Join(fields, ", ")))
	}

	milestoneRows := map[string][]string{}
	backings := self.rowBackings(literals)
	for _, rowId := range slices.Sorted(maps.Keys(self.fieldMap.Rows)) {
		entry := self.fieldMap.Rows[rowId]
		if entry.Planned == "" {
			continue
		}
		if 0 < len(backings[rowId]) {
			reports = append(reports, fmt.Sprintf("row %s has a value behind it and can drop planned: %s", rowId, entry.Planned))
			continue
		}
		milestoneRows[entry.Planned] = append(milestoneRows[entry.Planned], rowId)
	}
	for _, milestone := range slices.Sorted(maps.Keys(milestoneRows)) {
		reports = append(reports, fmt.Sprintf("%d rows nothing backs until %s: %s", len(milestoneRows[milestone]), milestone, strings.Join(milestoneRows[milestone], ", ")))
	}
	return reports, nil
}

// Classifies every key the stores hold: a family a literal hid still shows here. Each finding names
// the family and a key under it, sorted. An error means a store could not be read, which is no pass.
func (self *SchemaGuard) CheckStores(ctx context.Context, stores *SchemaGuardStores) ([]string, error) {
	if stores == nil || (stores.Blobs == nil && len(stores.RedisKeys) == 0) {
		return nil, errors.New("no store to read")
	}
	familyKeys := map[string]string{}
	note := func(key string, family MetadataFamily, where string) {
		if _, listed := self.familyRows[family]; listed {
			return
		}
		name := fmt.Sprintf("%s family %s", family.Kind, family.Name)
		if _, noted := familyKeys[name]; !noted {
			familyKeys[name] = fmt.Sprintf("%s holds %s", where, key)
		}
	}
	if stores.Blobs != nil {
		clusters, err := schemaGuardClusters(stores.Blobs)
		if err != nil {
			return nil, err
		}
		for _, cluster := range clusters {
			err := schemaGuardListKeys(ctx, cluster, func(key string) {
				note(key, schemaGuardObjectFamily(key), "cluster "+cluster.ClusterId())
			})
			if err != nil {
				return nil, err
			}
		}
	}
	for _, key := range stores.RedisKeys {
		note(key, schemaGuardRedisFamily(key), "Redis")
	}
	findings := []string{}
	for _, name := range slices.Sorted(maps.Keys(familyKeys)) {
		findings = append(findings, fmt.Sprintf("%s is in no row of metadata_list.yml: %s", name, familyKeys[name]))
	}
	return findings, nil
}

// Every cluster a store has: each metadata cluster, then the segment cluster.
func schemaGuardClusters(blobs sidecar.BlobStore) ([]sidecar.BlobCluster, error) {
	clusters := []sidecar.BlobCluster{}
	for _, clusterId := range blobs.MetadataClusterIds() {
		cluster, err := blobs.Cluster(clusterId)
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, cluster)
	}
	segmentCluster, err := blobs.SegmentCluster()
	if err != nil {
		return nil, err
	}
	return append(clusters, segmentCluster), nil
}

// Calls see on each of a cluster's keys, a page at a time.
func schemaGuardListKeys(ctx context.Context, cluster sidecar.BlobCluster, see func(key string)) error {
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, "", startAfter, schemaGuardListPageCount)
		if err != nil {
			return fmt.Errorf("listing cluster %s: %w", cluster.ClusterId(), err)
		}
		for _, object := range objects {
			see(object.Key)
			startAfter = object.Key
		}
		if !more {
			return nil
		}
	}
}
