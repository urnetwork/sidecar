package sidecartest

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/urnetwork/sidecar"
)

// The guard passes on the tree as it stands, and says what it leaned on. check/ runs this test too, and
// prints these lines at the end of make check.
func TestSchemaGuard(t *testing.T) {
	guard, err := LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := guard.Check()
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Error(finding)
	}
	reports, err := guard.Reports()
	if err != nil {
		t.Fatal(err)
	}
	for _, report := range reports {
		t.Log("schema guard: " + report)
	}
}

// §22.7 puts format 2's values in scope from the start, ahead of the code that sets them.
func TestSchemaGuardMapsFormat2sValues(t *testing.T) {
	guard, err := LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"EvsEntryVersion.versioning", "EvsLocator.kind", "EvsLocator.staged", "EvsPush.drop_sha256",
		"EvsPush.index_epoch", "EvsHead.index_epoch", "EvsUploadReceipt.versionless",
	} {
		if _, mapped := guard.fieldMap.Fields[field]; !mapped {
			t.Errorf("%s is in no row", field)
		}
	}
	for _, value := range []string{
		"EvsLocatorKind.EVS_LOCATOR_VERSIONLESS_SEGMENT", "EvsWindowFlag.EVS_WINDOW_VERSIONLESS_REPLACED",
		"EvsWindowFlag.EVS_WINDOW_DROP", "EvsPushFlag.EVS_PUSH_DROP", "EvsPushFlag.EVS_PUSH_CUT",
		"EvsVersioning.EVS_VERSIONING_VERSIONLESS", "EvsVersioning.EVS_VERSIONING_INDEX",
	} {
		if _, mapped := guard.fieldMap.EnumValues[value]; !mapped {
			t.Errorf("%s is in no row", value)
		}
	}
	purgeTimes := 0
	for value := range guard.fieldMap.Values {
		if strings.Contains(value, "purged") {
			purgeTimes += 1
		}
	}
	if purgeTimes < 2 {
		t.Errorf("%d purge times in the map, and evs-4 and evs-5 each show one", purgeTimes)
	}
}

// §22.7's guard carries v8's rows, these four by name, whose values land after M1.
func TestSchemaGuardCarriesV8sRows(t *testing.T) {
	guard, err := LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	for _, rowId := range []string{"connect-5", "evs-26", "evs-27", "evs-28"} {
		row := guard.list.Row(rowId)
		if row == nil || !row.Live() {
			t.Errorf("%s is no live row", rowId)
		}
		if entry := guard.fieldMap.Rows[rowId]; entry == nil || entry.Planned == "" {
			t.Errorf("%s has no line saying when its values land", rowId)
		}
	}
}

// Roots matter: what the design seals stays out of the map, whichever class seals it, or the guard
// would mark client data as server-visible.
func TestSchemaGuardKeepsSealedFieldsOutOfTheMap(t *testing.T) {
	guard, err := LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	for _, messageName := range []string{
		"SearchRequest", "RecordHeader", "ApprovalRequest", "IndexSettings", "DirectoryCard", "MailAuthEvidence",
		"HeadCheck", "BridgeRouteBody", "BridgeState", "WindowDelegation", "RecoveryBindBody", "EvsImport",
	} {
		for field := range guard.fieldMap.Fields {
			if strings.HasPrefix(field, messageName+".") {
				t.Errorf("%s is sealed, and the map gives %s a row", messageName, field)
			}
		}
	}
}

// The test tree's list: rows for each kind of backing, and one withdrawn.
const testGuardList = `# metadata_list.yml v1
evs-1:
  service: evs
  store: head/<repo>/<ref> (metadata cluster); Redis {evsh_<repo_id>}
  sees: the commit point
  why: commits
  ttl: the repo's life
  owner: §11.8
evs-2:
  service: evs
  store: Redis {acl_<networkId>}e and {acl_<networkId>}q
  sees: a cache
  why: reads
  ttl: 10 min
  owner: §11.8
api-1:
  service: api
  store: network_thing
  sees: a thing
  why: things
  ttl: its life
  owner: §7.6
ext-1:
  service: a third party
  store: external
  sees: what it sees
  why: its use
  ttl: its own
  owner: §7.8
evs-3:
  withdrawn: gone
`

// The test tree's map, which every line of holds true of the test tree's descriptors.
const testGuardMap = `landed: M2
roots:
  Root: "a server decodes it"
seals:
  Root.sealed_body: RootBody
sealed_messages:
  PeerOnly: "peers only"
fields:
  Root.repo_id: evs-1
  Root.child: evs-1
  Root.sealed_body: evs-1
  Child.version: evs-2
enum_values:
  Flag.FLAG_NONE: evs-2
  Flag.FLAG_DROP: evs-2
rows:
  api-1: {server: [network_thing]}
  ext-1: {planned: M5}
`

// A tree a guard can read, whose pieces each test changes before it asks.
type testGuardTree struct {
	t        *testing.T
	root     string
	list     string
	fieldMap string
	file     *descriptorpb.FileDescriptorProto
}

// A descriptor field.
func testGuardField(name string, number int32, fieldType descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
	field := &descriptorpb.FieldDescriptorProto{
		Name:   proto.String(name),
		Number: proto.Int32(number),
		Type:   fieldType.Enum(),
		Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
	}
	if typeName != "" {
		field.TypeName = proto.String(".urnetwork.sidecar." + typeName)
	}
	return field
}

// A descriptor message.
func testGuardMessage(name string, fields ...*descriptorpb.FieldDescriptorProto) *descriptorpb.DescriptorProto {
	return &descriptorpb.DescriptorProto{Name: proto.String(name), Field: fields}
}

// A clean tree: Root reaches Child, seals RootBody, and PeerOnly is sealed by name.
func newTestGuardTree(t *testing.T) *testGuardTree {
	return &testGuardTree{
		t:        t,
		root:     t.TempDir(),
		list:     testGuardList,
		fieldMap: testGuardMap,
		file: &descriptorpb.FileDescriptorProto{
			Name:    proto.String("protocol/planted.proto"),
			Package: proto.String(schemaGuardProtoPackage),
			Syntax:  proto.String("proto3"),
			MessageType: []*descriptorpb.DescriptorProto{
				testGuardMessage("Root",
					testGuardField("repo_id", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, ""),
					testGuardField("child", 2, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, "Child"),
					testGuardField("sealed_body", 3, descriptorpb.FieldDescriptorProto_TYPE_BYTES, ""),
				),
				testGuardMessage("Child", testGuardField("version", 1, descriptorpb.FieldDescriptorProto_TYPE_UINT64, "")),
				testGuardMessage("RootBody", testGuardField("secret", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "")),
				testGuardMessage("PeerOnly", testGuardField("pin", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "")),
			},
			EnumType: []*descriptorpb.EnumDescriptorProto{{
				Name: proto.String("Flag"),
				Value: []*descriptorpb.EnumValueDescriptorProto{
					{Name: proto.String("FLAG_NONE"), Number: proto.Int32(0)},
					{Name: proto.String("FLAG_DROP"), Number: proto.Int32(1)},
				},
			}},
		},
	}
}

// Writes a file under the tree's top.
func (self *testGuardTree) write(relativePath string, content string) {
	self.t.Helper()
	path := filepath.Join(self.root, relativePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		self.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		self.t.Fatal(err)
	}
}

// Replaces text in the map, which the test means to be there.
func (self *testGuardTree) editMap(old string, new string) {
	self.t.Helper()
	if !strings.Contains(self.fieldMap, old) {
		self.t.Fatalf("the map holds no %q", old)
	}
	self.fieldMap = strings.Replace(self.fieldMap, old, new, 1)
}

// The message of that name.
func (self *testGuardTree) message(name string) *descriptorpb.DescriptorProto {
	self.t.Helper()
	for _, message := range self.file.MessageType {
		if message.GetName() == name {
			return message
		}
	}
	self.t.Fatalf("no message %s", name)
	return nil
}

// A guard over the tree as it stands now.
func (self *testGuardTree) open() (*SchemaGuard, error) {
	self.t.Helper()
	self.write(metadataListFileName, self.list)
	self.write(schemaGuardFieldsPath, self.fieldMap)
	file, err := protodesc.NewFile(self.file, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	files := &protoregistry.Files{}
	if err := files.RegisterFile(file); err != nil {
		self.t.Fatal(err)
	}
	return NewSchemaGuard(&SchemaGuardSources{RootDirectory: self.root, Files: files})
}

// What the guard finds in the tree.
func (self *testGuardTree) findings() []string {
	self.t.Helper()
	guard, err := self.open()
	if err != nil {
		self.t.Fatal(err)
	}
	findings, err := guard.Check()
	if err != nil {
		self.t.Fatal(err)
	}
	return findings
}

// Wants exactly the findings wants, in order, each by what it names.
func wantGuardFindings(t *testing.T, findings []string, wants ...string) {
	t.Helper()
	if len(findings) != len(wants) {
		t.Fatalf("%d findings, want %d:\n%s", len(findings), len(wants), strings.Join(findings, "\n"))
	}
	for index, want := range wants {
		if !strings.Contains(findings[index], want) {
			t.Errorf("finding %d does not name %q:\n%s", index, want, findings[index])
		}
	}
}

func TestSchemaGuardPassesACleanTree(t *testing.T) {
	wantGuardFindings(t, newTestGuardTree(t).findings())
}

func TestSchemaGuardFailsOnAProtoFieldNoRowNames(t *testing.T) {
	tree := newTestGuardTree(t)
	root := tree.message("Root")
	root.Field = append(root.Field, testGuardField("new_value", 4, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""))
	wantGuardFindings(t, tree.findings(), "proto field Root.new_value, reachable from Root, maps to no row")
}

func TestSchemaGuardFailsOnANewFieldTwoMessagesDeep(t *testing.T) {
	tree := newTestGuardTree(t)
	child := tree.message("Child")
	child.Field = append(child.Field, testGuardField("flags", 2, descriptorpb.FieldDescriptorProto_TYPE_UINT32, ""))
	wantGuardFindings(t, tree.findings(), "proto field Child.flags, reachable from Root")
}

func TestSchemaGuardFailsOnAFieldMappedToAnUnknownRow(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("Child.version: evs-2", "Child.version: evs-9")
	wantGuardFindings(t, tree.findings(), "proto field Child.version maps to row evs-9, which metadata_list.yml does not hold")
}

func TestSchemaGuardFailsOnAFieldMappedToAWithdrawnRow(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("Child.version: evs-2", "Child.version: evs-3")
	wantGuardFindings(t, tree.findings(), "proto field Child.version maps to row evs-3, which is withdrawn")
}

// A map entry for a field gone from the proto would otherwise stay as a false account of what ships.
func TestSchemaGuardFailsOnAMappedFieldThatIsGone(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Child.version: evs-2\n", "  Child.version: evs-2\n  Child.gone: evs-2\n")
	wantGuardFindings(t, tree.findings(), "fields entry Child.gone is a field no root reaches")
}

// A field behind a sealed bytes needs no row, however many it holds, and the bytes itself does.
func TestSchemaGuardSkipsWhatASealHides(t *testing.T) {
	tree := newTestGuardTree(t)
	body := tree.message("RootBody")
	body.Field = append(body.Field, testGuardField("more_secret", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""))
	wantGuardFindings(t, tree.findings())
	tree.editMap("  Root.sealed_body: evs-1\n", "")
	wantGuardFindings(t, tree.findings(), "proto field Root.sealed_body, reachable from Root, maps to no row")
}

// A seal covers what the sealed message holds, unless a root reaches that too.
func TestSchemaGuardSealsWhatASealedMessageHolds(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.MessageType = append(tree.file.MessageType, testGuardMessage("Inner", testGuardField("text", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "")))
	body := tree.message("RootBody")
	body.Field = append(body.Field, testGuardField("inner", 2, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, "Inner"))
	wantGuardFindings(t, tree.findings())

	root := tree.message("Root")
	root.Field = append(root.Field, testGuardField("inner", 4, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, "Inner"))
	tree.editMap("  Child.version: evs-2\n", "  Child.version: evs-2\n  Root.inner: evs-1\n")
	wantGuardFindings(t, tree.findings(), "proto field Inner.text, reachable from Root, maps to no row")
}

// Every registered message lands in a class, so one nobody thought about fails.
func TestSchemaGuardFailsOnAMessageInNoClass(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.MessageType = append(tree.file.MessageType, testGuardMessage("Stray", testGuardField("value", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "")))
	wantGuardFindings(t, tree.findings(), "message Stray is in no class")
}

func TestSchemaGuardFailsOnASealedMessageARootReaches(t *testing.T) {
	tree := newTestGuardTree(t)
	root := tree.message("Root")
	root.Field = append(root.Field, testGuardField("peer", 4, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, "PeerOnly"))
	tree.editMap("  Child.version: evs-2\n", "  Child.version: evs-2\n  Root.peer: evs-1\n  PeerOnly.pin: evs-1\n")
	wantGuardFindings(t, tree.findings(), "message PeerOnly is called sealed, and root Root reaches it")
}

func TestSchemaGuardFailsOnASealOnAnythingButBytes(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Root.sealed_body: RootBody\n", "  Root.sealed_body: RootBody\n  Child.version: RootBody\n")
	wantGuardFindings(t, tree.findings(), "seal on Child.version: a seal is on bytes")
}

func TestSchemaGuardFailsOnARootThatIsGone(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Root: \"a server decodes it\"\n", "  Root: \"a server decodes it\"\n  Vanished: \"once\"\n")
	wantGuardFindings(t, tree.findings(), "root Vanished is no registered message")
}

// A file whose messages are sealed lets a root still claim one.
func TestSchemaGuardReadsASealedFile(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("sealed_messages:\n  PeerOnly: \"peers only\"\n", "sealed_files:\n  protocol/planted.proto: \"its messages are sealed\"\n")
	wantGuardFindings(t, tree.findings())
	tree.editMap("protocol/planted.proto", "protocol/other.proto")
	wantGuardFindings(t, tree.findings(), "message PeerOnly is in no class", "sealed file protocol/other.proto is not registered")
}

// An unset field needs no row, and what it would reach is not reached through it.
func TestSchemaGuardLetsAnUnsetFieldThrough(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Root.child: evs-1\n", "")
	tree.editMap("  Child.version: evs-2\n", "")
	tree.editMap("enum_values:", "unset:\n  Root.child: \"the rule that keeps it empty\"\nsealed_files:\n  protocol/planted.proto: \"sealed\"\nenum_values:")
	wantGuardFindings(t, tree.findings())
}

func TestSchemaGuardFailsOnAFieldInTwoSections(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("enum_values:", "unset:\n  Root.child: \"a rule\"\nenum_values:")
	wantGuardFindings(t, tree.findings(), "fields entry Child.version is a field no root reaches", "message Child is in no class", "proto field Root.child sits in more than one")
}

// An open field passes while its question is open and fails from the milestone it names.
func TestSchemaGuardHoldsAnOpenFieldToItsMilestone(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Child.version: evs-2\n", "")
	tree.editMap("enum_values:", "open:\n  Child.version: {row: evs-2, question: a-question.md, until: M3}\nenum_values:")
	wantGuardFindings(t, tree.findings())

	guard, err := tree.open()
	if err != nil {
		t.Fatal(err)
	}
	reports, err := guard.Reports()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(reports, func(report string) bool {
		return strings.Contains(report, "Child.version") && strings.Contains(report, "a-question.md") && strings.Contains(report, "M3")
	}) {
		t.Errorf("no report names the open field:\n%s", strings.Join(reports, "\n"))
	}

	tree.editMap("landed: M2", "landed: M3")
	wantGuardFindings(t, tree.findings(), "open field Child.version: M3 has landed and a-question.md is still open")
}

func TestSchemaGuardFailsOnAnOpenFieldWithNoQuestion(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Child.version: evs-2\n", "")
	tree.editMap("enum_values:", "open:\n  Child.version: {row: evs-2, until: M3}\nenum_values:")
	wantGuardFindings(t, tree.findings(), "open field Child.version names no question")
}

// An open field is not yet in §2.8, so it backs no row.
func TestSchemaGuardCountsNoOpenFieldAsBacking(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Child.version: evs-2\n", "")
	tree.editMap("  Flag.FLAG_NONE: evs-2\n  Flag.FLAG_DROP: evs-2\n", "  Flag.FLAG_NONE: evs-1\n  Flag.FLAG_DROP: evs-1\n")
	tree.editMap("enum_values:", "open:\n  Child.version: {row: evs-2, question: a-question.md, until: M3}\nenum_values:")
	wantGuardFindings(t, tree.findings(), "row evs-2: nothing backs it")
}

// A new flag bit has no field to show up in, so its enum is mapped whole.
func TestSchemaGuardFailsOnANewValueOfAMappedEnum(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.EnumType[0].Value = append(tree.file.EnumType[0].Value, &descriptorpb.EnumValueDescriptorProto{Name: proto.String("FLAG_CUT"), Number: proto.Int32(2)})
	wantGuardFindings(t, tree.findings(), "enum value Flag.FLAG_CUT maps to no row")
}

func TestSchemaGuardFailsOnAnEnumValueThatIsGone(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Flag.FLAG_DROP: evs-2\n", "  Flag.FLAG_DROP: evs-2\n  Flag.FLAG_GONE: evs-2\n")
	wantGuardFindings(t, tree.findings(), "enum value Flag.FLAG_GONE is no registered value")
}

func TestSchemaGuardFailsOnALiveRowNothingBacks(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  ext-1: {planned: M5}\n", "")
	wantGuardFindings(t, tree.findings(), "row ext-1: nothing backs it")
}

func TestSchemaGuardFailsOnAPlannedMilestoneThatHasPassed(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("ext-1: {planned: M5}", "ext-1: {planned: M2}")
	wantGuardFindings(t, tree.findings(), "row ext-1: planned: M2, and M2 has landed")
}

// A value a row's prose alone names backs its row through a map entry, not by being skipped.
func TestSchemaGuardTakesAProseValueAsBacking(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  ext-1: {planned: M5}\n", "")
	tree.editMap("rows:", "values:\n  \"what the third party sees\": ext-1\nrows:")
	wantGuardFindings(t, tree.findings())
	tree.editMap("what the third party sees\": ext-1", "what the third party sees\": ext-9")
	wantGuardFindings(t, tree.findings(), "row ext-1: nothing backs it", "value what the third party sees maps to row ext-9")
}

func TestSchemaGuardFailsOnServerBackingTheRowDoesNotName(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("server: [network_thing]", "server: [network_other]")
	wantGuardFindings(t, tree.findings(), "row api-1 says server's network_other backs it")
}

func TestSchemaGuardFailsOnARowsEntryForAWithdrawnRow(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("rows:\n", "rows:\n  evs-3: {planned: M5}\n")
	wantGuardFindings(t, tree.findings(), "the rows section names row evs-3, which is withdrawn")
}

func TestSchemaGuardReportsAPlannedRowThatIsBacked(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("rows:\n", "rows:\n  evs-1: {planned: M5}\n")
	guard, err := tree.open()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := guard.Check()
	if err != nil {
		t.Fatal(err)
	}
	wantGuardFindings(t, findings)
	reports, err := guard.Reports()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(reports, func(report string) bool {
		return strings.Contains(report, "row evs-1 has a value behind it and can drop planned")
	}) {
		t.Errorf("nothing says evs-1 can drop planned:\n%s", strings.Join(reports, "\n"))
	}
}

func TestSchemaGuardFailsOnANewObjectFamily(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("evsservice/objects.go", `package evsservice

func headKey(repoId string, refId string) string { return "head/" + repoId + "/" + refId }
func auditKey(repoId string) string { return "audit/" + repoId }
`)
	wantGuardFindings(t, tree.findings(), `object family audit/, from "audit/<>" at evsservice/objects.go:4, is in no row`)
}

func TestSchemaGuardFailsOnANewRedisFamily(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("evsservice/redis.go", `package evsservice

import "fmt"

func cacheKey(repoId string) string { return "{evsh_" + repoId + "}" }
func traceKey(repoId string) string { return fmt.Sprintf("{evst_%s}", repoId) }
`)
	wantGuardFindings(t, tree.findings(), `redis family {evst_}, from "{evst_<>}" at evsservice/redis.go:6, is in no row`)
}

// {acl_}e and {acl_}q are separate families, so a third under the tag is a new one.
func TestSchemaGuardKeepsRedisSuffixesApart(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("gkmservice/redis.go", `package gkmservice

func entryKey(networkId string) string { return "{acl_" + networkId + "}e" }
func limitKey(networkId string) string { return "{acl_" + networkId + "}q" }
func otherKey(networkId string) string { return "{acl_" + networkId + "}z" }
`)
	wantGuardFindings(t, tree.findings(), `redis family {acl_}z, from "{acl_<>}z" at gkmservice/redis.go:5`)
}

// A constant that stops inside the tag names no suffix, so it stands for any family under that tag.
func TestSchemaGuardReadsALiteralThatStopsInsideATag(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("gkmservice/redis.go", `package gkmservice

const aclPrefix = "{acl_"
const strayPrefix = "{stray_"
`)
	wantGuardFindings(t, tree.findings(), `redis family {stray_}, from "{stray_" at gkmservice/redis.go:4`)
}

// A suffix built at run time shows only the tag, so what the tag starts is all that can be held.
func TestSchemaGuardReadsASuffixBuiltAtRunTime(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("gkmservice/redis.go", `package gkmservice

func aclKey(networkId string, suffix string) string { return "{acl_" + networkId + "}" + suffix }
func strayKey(networkId string, suffix string) string { return "{stray_" + networkId + "}" + suffix }
`)
	wantGuardFindings(t, tree.findings(), `redis family {stray_}, from "{stray_<>}<>" at gkmservice/redis.go:4`)
}

// A family literal backs its row, so a planned row with one has what it was waiting for.
func TestSchemaGuardTakesALiteralAsBacking(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.editMap("  Child.version: evs-2\n", "")
	tree.editMap("  Flag.FLAG_NONE: evs-2\n  Flag.FLAG_DROP: evs-2\n", "  Flag.FLAG_NONE: evs-1\n  Flag.FLAG_DROP: evs-1\n")
	tree.editMap("enum_values:", "open:\n  Child.version: {row: evs-1, question: a-question.md, until: M3}\nenum_values:")
	wantGuardFindings(t, tree.findings(), "row evs-2: nothing backs it")
	tree.write("evsservice/redis.go", "package evsservice\n\nconst entryFormat = \"{acl_%s}e\"\n")
	wantGuardFindings(t, tree.findings())
}

// Key builders outside <svc>service join through the map's key_sources.
func TestSchemaGuardReadsAKeySource(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("evs_repo_place.go", "package sidecar\n\nconst placePrefix = \"place/\"\n")
	wantGuardFindings(t, tree.findings())
	tree.editMap("roots:", "key_sources:\n  - evs_repo_place.go\nroots:")
	wantGuardFindings(t, tree.findings(), `object family place/, from "place/"`)
}

// Strings that are no key stay out: imports, tags, media types, prose, tests.
func TestSchemaGuardReadsOnlyKeyShapes(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("evsservice/engine.go", "package evsservice\n\nimport \"net/http\"\n\ntype row struct {\n\tid string `json:\"a/b\"`\n}\n\nconst mediaType = \"application/octet-stream\"\nconst sentence = \"either/or as prose\"\nconst route = \"/evs/v1/repos/\"\n\nvar client = http.Client{}\n")
	tree.write("evsservice/engine_test.go", "package evsservice\n\nconst planted = \"strange/\"\n")
	wantGuardFindings(t, tree.findings())
}

// A literal that reads as a key and is none gets a line saying what it is, and that line goes when
// the literal does.
func TestSchemaGuardTakesANotKeysEntry(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("socketsservice/names.go", "package socketsservice\n\nconst tlsNamePrefix = \"tls/\"\n")
	wantGuardFindings(t, tree.findings(), `object family tls/, from "tls/"`)
	tree.editMap("rows:", "not_keys:\n  \"tls/\": \"a socket name's prefix (§9.4)\"\nrows:")
	wantGuardFindings(t, tree.findings())
	tree.write("socketsservice/names.go", "package socketsservice\n")
	wantGuardFindings(t, tree.findings(), `not_keys entry "tls/" matches no literal`)
}

// An area's file maps its own fields, and a message it names is a root.
func TestSchemaGuardReadsAnAreasRows(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.MessageType = append(tree.file.MessageType, testGuardMessage("AreaThing", testGuardField("value", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "")))
	tree.write("testdata/evs/format2/"+schemaGuardAreaFileName, "AreaThing.value: {row: evs-1, sees: \"commit point\"}\n")
	wantGuardFindings(t, tree.findings())
}

// A message an area names is whole in the map: a field its file forgot fails.
func TestSchemaGuardHoldsAnAreasMessageWhole(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.MessageType = append(tree.file.MessageType, testGuardMessage("AreaThing",
		testGuardField("value", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, ""),
		testGuardField("forgotten", 2, descriptorpb.FieldDescriptorProto_TYPE_BYTES, ""),
	))
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "AreaThing.value: {row: evs-1, sees: \"commit point\"}\n")
	wantGuardFindings(t, tree.findings(), "proto field AreaThing.forgotten, reachable from AreaThing, maps to no row")
}

// sees quotes the row, so the row is what stops it passing.
func TestSchemaGuardHoldsAnAreasQuoteToItsRow(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.MessageType = append(tree.file.MessageType, testGuardMessage("AreaThing", testGuardField("value", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "")))
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "AreaThing.value: {row: evs-1, sees: \"commit point\"}\n")
	tree.list = strings.Replace(tree.list, "sees: the commit point", "sees: something else", 1)
	wantGuardFindings(t, tree.findings(), `proto field AreaThing.value quotes "commit point", and row evs-1 no longer says that`)
}

// number and type pin a message no design fence pins.
func TestSchemaGuardHoldsAnAreasNumberAndType(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.MessageType = append(tree.file.MessageType, testGuardMessage("AreaThing", testGuardField("value", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "")))
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "AreaThing.value: {number: 1, type: bytes, row: evs-1, sees: \"commit point\"}\n")
	wantGuardFindings(t, tree.findings())
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "AreaThing.value: {number: 2, type: string, row: evs-1, sees: \"commit point\"}\n")
	wantGuardFindings(t, tree.findings(), "proto field AreaThing.value is bytes, and its line says string", "proto field AreaThing.value is number 1, and its line says 2")
}

// A pending line is an open field: it backs nothing, and fails from the map's pending_until.
func TestSchemaGuardHoldsAPendingLineToItsMilestone(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.MessageType = append(tree.file.MessageType, testGuardMessage("AreaThing", testGuardField("value", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "")))
	tree.editMap("landed: M2", "landed: M2\npending_until: M3")
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "AreaThing.value: {row: evs-1, pending: \"the row does not say it\"}\n")
	wantGuardFindings(t, tree.findings())
	tree.editMap("landed: M2", "landed: M3")
	wantGuardFindings(t, tree.findings(), "open field AreaThing.value: M3 has landed and testdata/evs/metadata_rows.yml is still open")
}

// A line naming its own milestone keeps to that one.
func TestSchemaGuardLetsAPendingLineNameItsMilestone(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.file.MessageType = append(tree.file.MessageType, testGuardMessage("AreaThing", testGuardField("value", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "")))
	tree.editMap("landed: M2", "landed: M3\npending_until: M3")
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "AreaThing.value: {row: evs-1, pending: \"a format 2 value\", until: M10}\n")
	wantGuardFindings(t, tree.findings())
}

func TestSchemaGuardRefusesALineWithNeitherQuoteNorPending(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "Root.value: {row: evs-1}\n")
	if _, err := tree.open(); err == nil || !strings.Contains(err.Error(), "exactly one of sees and pending") {
		t.Errorf("error %v", err)
	}
}

func TestSchemaGuardRefusesOneFieldInTwoFiles(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "Root.repo_id: {row: evs-2, sees: \"a cache\"}\n")
	if _, err := tree.open(); err == nil || !strings.Contains(err.Error(), "Root.repo_id is mapped twice") {
		t.Errorf("error %v", err)
	}
}

func TestSchemaGuardReadsAnAreaStrictly(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write("testdata/evs/"+schemaGuardAreaFileName, "Root.value: {row: evs-1, sees: \"x\", skip: true}\n")
	if _, err := tree.open(); err == nil || !strings.Contains(err.Error(), "skip") {
		t.Errorf("error %v", err)
	}
}

func TestSchemaGuardReadsTheMapStrictly(t *testing.T) {
	for _, planted := range []struct {
		old  string
		new  string
		want string
	}{
		{old: "landed: M2", new: "landed: soon", want: "is no milestone"},
		{old: "roots:", new: "skip:\n  Root: \"no\"\nroots:", want: "skip"},
		{old: "  Root.repo_id: evs-1\n", new: "  Root.repo_id: evs-1\n  Root.repo_id: evs-2\n", want: "already defined"},
		{old: "  Root: \"a", new: "\tRoot: \"a", want: "holds a tab"},
		{old: "ext-1: {planned: M5}", new: "ext-1: {planned: M5, skip: true}", want: "skip"},
		{old: "  ext-1: {planned: M5}\n", new: "  ext-1: &later {planned: M5}\n  evs-2: *later\n", want: "holds an alias"},
	} {
		tree := newTestGuardTree(t)
		tree.editMap(planted.old, planted.new)
		if _, err := tree.open(); err == nil || !strings.Contains(err.Error(), planted.want) {
			t.Errorf("planting %q: error %v", planted.new, err)
		}
	}
}

func TestSchemaGuardFailsWithNoMap(t *testing.T) {
	tree := newTestGuardTree(t)
	tree.write(metadataListFileName, tree.list)
	if _, err := NewSchemaGuard(&SchemaGuardSources{RootDirectory: tree.root, Files: &protoregistry.Files{}}); err == nil {
		t.Errorf("built a guard with no map")
	}
}

// The test tree's stores, for CheckStores: a key per family its list names.
func newTestGuardStores(t *testing.T) (*FakeBlobs, *FakeRedis) {
	t.Helper()
	blobs := NewFakeBlobs(nil, nil, nil, nil)
	redis := NewFakeRedis(context.Background(), nil, nil, nil, nil)
	t.Cleanup(redis.Close)
	return blobs, redis
}

// Puts an object on a cluster.
func putTestObject(t *testing.T, blobs *FakeBlobs, clusterId string, key string) {
	t.Helper()
	cluster, err := blobs.Cluster(clusterId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(context.Background(), key, []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
}

// Sets a Redis key.
func setTestRedisKey(t *testing.T, redis *FakeRedis, key string) {
	t.Helper()
	if err := redis.Set(context.Background(), key, []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
}

// The findings CheckStores gives on the fakes.
func checkTestStores(t *testing.T, blobs *FakeBlobs, redis *FakeRedis) []string {
	t.Helper()
	guard, err := newTestGuardTree(t).open()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := guard.CheckStores(context.Background(), &SchemaGuardStores{
		Blobs:     blobs,
		RedisKeys: slices.Collect(maps.Keys(redis.Dump())),
	})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestCheckStoresPassesListedFamilies(t *testing.T) {
	blobs, redis := newTestGuardStores(t)
	putTestObject(t, blobs, "meta-1", "head/ab/cd")
	setTestRedisKey(t, redis, "{evsh_ab}")
	setTestRedisKey(t, redis, "{acl_cd}e")
	setTestRedisKey(t, redis, "{acl_cd}q")
	wantGuardFindings(t, checkTestStores(t, blobs, redis))
}

// A family a literal hid still shows at run time: the key is under no listed prefix.
func TestCheckStoresCatchesAnUnlistedObjectPrefix(t *testing.T) {
	blobs, redis := newTestGuardStores(t)
	putTestObject(t, blobs, "meta-1", "head/ab/cd")
	putTestObject(t, blobs, "seg-1", "hidden/ab")
	wantGuardFindings(t, checkTestStores(t, blobs, redis), "object family hidden/ is in no row of metadata_list.yml: cluster seg-1 holds hidden/ab")
}

func TestCheckStoresCatchesAnUnlistedRedisFamily(t *testing.T) {
	blobs, redis := newTestGuardStores(t)
	setTestRedisKey(t, redis, "{evsx_ab}")
	wantGuardFindings(t, checkTestStores(t, blobs, redis), "redis family {evsx_} is in no row of metadata_list.yml: Redis holds {evsx_ab}")
}

func TestCheckStoresKeepsSuffixesApart(t *testing.T) {
	blobs, redis := newTestGuardStores(t)
	setTestRedisKey(t, redis, "{acl_ab}e")
	setTestRedisKey(t, redis, "{acl_ab}z")
	wantGuardFindings(t, checkTestStores(t, blobs, redis), "redis family {acl_}z is in no row")
}

// One finding per family, however many keys sit under it.
func TestCheckStoresNamesAFamilyOnce(t *testing.T) {
	blobs, redis := newTestGuardStores(t)
	putTestObject(t, blobs, "meta-1", "hidden/1")
	putTestObject(t, blobs, "meta-1", "hidden/2")
	wantGuardFindings(t, checkTestStores(t, blobs, redis), "object family hidden/")
}

// Every key is read, past one page.
func TestCheckStoresReadsEveryPage(t *testing.T) {
	blobs, redis := newTestGuardStores(t)
	for index := range schemaGuardListPageCount + 1 {
		putTestObject(t, blobs, "meta-1", "head/"+strings.Repeat("a", index%7)+"-"+strings.Repeat("b", index/7)+"/x")
	}
	putTestObject(t, blobs, "meta-1", "zzz/last")
	wantGuardFindings(t, checkTestStores(t, blobs, redis), "object family zzz/")
}

// No stores read is no pass.
func TestCheckStoresRefusesNoStores(t *testing.T) {
	guard, err := newTestGuardTree(t).open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.CheckStores(context.Background(), &SchemaGuardStores{}); err == nil {
		t.Errorf("read nothing and passed")
	}
	if _, err := guard.CheckStores(context.Background(), nil); err == nil {
		t.Errorf("read nothing and passed")
	}
}

// A store that does not answer is no pass either.
func TestCheckStoresFailsOnAStoreItCannotRead(t *testing.T) {
	blobs, _ := newTestGuardStores(t)
	guard, err := newTestGuardTree(t).open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.CheckStores(context.Background(), &SchemaGuardStores{Blobs: blobs.View("meta-1")}); err == nil {
		t.Errorf("a view with no segment cluster passed")
	}
}

// The real list and map on a store: a family §2.8 names passes, and a hidden one does not.
func TestCheckStoresReadsTheRealList(t *testing.T) {
	guard, err := LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	blobs := NewFakeBlobs(nil, nil, nil, nil)
	putTestObject(t, blobs, "meta-1", "gkm/kp/ab/cd.claim")
	putTestObject(t, blobs, "seg-1", "seg/ab/cd")
	findings, err := guard.CheckStores(context.Background(), &SchemaGuardStores{
		Blobs:     blobs,
		RedisKeys: []string{"{scp_c}ver", "{scp_c}tokrev", "{sg_n_h}ix", "{dns}serial:ur.example", "{nvb_set}", "{wakeq_3}"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantGuardFindings(t, findings)
	findings, err = guard.CheckStores(context.Background(), &SchemaGuardStores{Blobs: blobs, RedisKeys: []string{"{scp_c}other", "untagged"}})
	if err != nil {
		t.Fatal(err)
	}
	wantGuardFindings(t, findings, "redis family untagged", "redis family {scp_}other")
}

// sidecar's own types, so a change to the host's interface shows here rather than at T3.
var _ sidecar.BlobStore = (*FakeBlobs)(nil)
