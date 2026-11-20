// §7.9's ServiceSettings on the test network: the bounds a head's settings keep, a full reader forking on a head outside
// them, the head-only values' defaults at a full reader and unknown at a rows-only one, scim_signer from rows, and
// FS-72's format-1 cases: a head holding VersioningRules or a ServiceSettings.directory compiles and applies with
// nothing taken from either. Then the Settings fields (owner decisions 302, 305; QD-204): their defaults and the head's
// values at a full reader, their closed values at a rows-only one, a Team named by its directory, and a reader whose
// config.proto lacks them skipping them and keeping them through a re-sign.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// witness_bound_hours 0 or 24 to 168; known enum values, record_cost's among them; a scim_signer of none or a sidecar_id;
// mail_strict and record_required either way.
func TestServiceSettingsBounds(t *testing.T) {
	cases := []struct {
		name     string
		settings *protocol.ServiceSettings
		ok       bool
	}{
		{name: "none", settings: nil, ok: true},
		{name: "the defaults", settings: &protocol.ServiceSettings{}, ok: true},
		{name: "24 hours", settings: &protocol.ServiceSettings{WitnessBoundHours: 24}, ok: true},
		{name: "168 hours", settings: &protocol.ServiceSettings{WitnessBoundHours: 168}, ok: true},
		{name: "23 hours", settings: &protocol.ServiceSettings{WitnessBoundHours: 23}, ok: false},
		{name: "169 hours", settings: &protocol.ServiceSettings{WitnessBoundHours: 169}, ok: false},
		{name: "an unknown self_admit", settings: &protocol.ServiceSettings{SelfAdmit: protocol.SelfAdmitMode(7)}, ok: false},
		{name: "an unknown team_mail", settings: &protocol.ServiceSettings{TeamMail: protocol.TeamMailMode(7)}, ok: false},
		{name: "a short scim_signer", settings: &protocol.ServiceSettings{ScimSigner: []byte{1, 2, 3}}, ok: false},
		{name: "a scim_signer", settings: &protocol.ServiceSettings{ScimSigner: testConfigId("indexer").Bytes()}, ok: true},
		{name: "a directory, ignored at M2", settings: &protocol.ServiceSettings{Directory: &protocol.ServiceDirectorySettings{Runs: 9}}, ok: true},
		{name: "the Settings fields set", settings: &protocol.ServiceSettings{MailStrict: true, RecordCost: protocol.RecordCostMode_RECORD_COST_MODE_OFF, RecordRequired: true}, ok: true},
		{name: "record_cost on", settings: &protocol.ServiceSettings{RecordCost: protocol.RecordCostMode_RECORD_COST_MODE_ON}, ok: true},
		{name: "an unknown record_cost", settings: &protocol.ServiceSettings{RecordCost: protocol.RecordCostMode(3)}, ok: false},
	}
	for _, c := range cases {
		if err := CheckServiceSettings(c.settings); (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrConfigRule)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A full reader whose base's head holds a witness_bound_hours outside 24-168 forks at that base.
func TestAHeadWithSettingsOutOfBoundsForks(t *testing.T) {
	net := newTestConfigNet(t)
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(2))] = &protocol.ServiceSettings{WitnessBoundHours: 200}
	entry := net.makeBase(net.owner, net.log.State().Rows(), net.n, 2, 0)
	if _, err := net.log.Apply(entry, net.source); !errors.Is(err, ErrConfigFork) {
		t.Fatalf("the base: %v", err)
	}
}

// The head-only values default at a full reader, 90 days and 72 hours, take the head's when it sets them, and are
// unknown at a rows-only reader; scim_signer comes from rows at both.
func TestHeadOnlySettingsAndScimSigner(t *testing.T) {
	net := newTestConfigNet(t)
	if days, known := net.log.State().StaleLeafDays(); !known || days != 90 {
		t.Errorf("stale_leaf_days %d, known %v", days, known)
	}
	if hours, known := net.log.State().WitnessBoundHours(); !known || hours != 72 {
		t.Errorf("witness_bound_hours %d, known %v", hours, known)
	}
	if _, set := net.log.State().ScimSigner(); set {
		t.Error("a scim_signer with none set")
	}
	indexer := testConfigId("admin indexer")
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(2))] = &protocol.ServiceSettings{
		StaleLeafDays: 30, WitnessBoundHours: 24, ScimSigner: indexer.Bytes(),
	}
	net.fold(net.owner, net.n, 2)
	state := net.log.State()
	if days, _ := state.StaleLeafDays(); days != 30 {
		t.Errorf("stale_leaf_days %d", days)
	}
	if hours, _ := state.WitnessBoundHours(); hours != 24 {
		t.Errorf("witness_bound_hours %d", hours)
	}
	if signer, set := state.ScimSigner(); !set || signer != indexer {
		t.Errorf("scim_signer %s, set %v", signer, set)
	}
	gate := net.everyReader()[2]
	if _, known := gate.State().WitnessBoundHours(); known {
		t.Error("a rows-only reader knows witness_bound_hours")
	}
	if signer, set := gate.State().ScimSigner(); !set || signer != indexer {
		t.Errorf("the gate's scim_signer %s, set %v", signer, set)
	}
}

// FS-72's format-1 cases: a head holding VersioningRules, and one whose ServiceSettings carries a directory, compile and
// pass the base check, taking nothing from VersioningRules and only self_admit and scim_signer from ServiceSettings.
func TestAHeadsVersioningRulesAndDirectoryApplyNothing(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	plain := testConfigHead(t, net)
	versioning := net.sign(net.owner, bridge.SignedType_SIGNED_VERSIONING_RULES, &protocol.VersioningRules{
		Rules: []*protocol.VersioningRule{{SizeAboveBytes: 1024, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF}},
	})
	withVersioning, err := plain.WithFile(ConfigHeadVersioningRulesPath, versioning)
	if err != nil {
		t.Fatal(err)
	}
	settings := net.sign(net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, &protocol.ServiceSettings{
		Directory: &protocol.ServiceDirectorySettings{Runs: protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF},
	})
	withDirectory, err := withVersioning.WithFile(ConfigHeadServiceSettingsPath, settings)
	if err != nil {
		t.Fatal(err)
	}
	rows := ConfigCompileRowsOf(net.log.State())
	want, err := CompileProjectionRows(plain, rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, head := range []*ConfigHead{withVersioning, withDirectory} {
		compiled, err := CompileProjectionRows(head, rows)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(compiled, want) {
			t.Error("a head's VersioningRules or directory reached its rows")
		}
		facts, err := CheckConfigBase(head, &ConfigHeadCheck{
			Previous: net.log.State(), Header: &bridge.ProjectionHeader{FoldedThrough: 0}, FoldedKnown: true, Rows: compiled,
		}, rows)
		if err != nil {
			t.Fatalf("the base check: %v", err)
		}
		if head == withDirectory && facts.Settings.GetDirectory().GetRuns() != protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF {
			t.Error("the head check lost the directory a device reads at M6")
		}
	}
}

// The Settings fields at a full reader: mail_strict and record_required off and record_cost on with no settings or none
// of them set, the head's values once it sets them, record_cost on again by its explicit value; at a rows-only reader
// not known, each at its closed value, record_cost off though the head leaves it on; and a Team once the config names a
// directory.
func TestServiceSettingsFieldsDefaultsAndClosedValues(t *testing.T) {
	net := newTestConfigNet(t)
	if honored := net.log.State().TeamSettings(); *honored != (ConfigTeamSettings{Known: true, RecordCost: true}) {
		t.Fatalf("the defaults: %+v", honored)
	}
	cases := []struct {
		settings *protocol.ServiceSettings
		want     ConfigTeamSettings
	}{
		{
			settings: &protocol.ServiceSettings{WitnessBoundHours: 48},
			want:     ConfigTeamSettings{Known: true, RecordCost: true},
		},
		{
			settings: &protocol.ServiceSettings{MailStrict: true, RecordCost: protocol.RecordCostMode_RECORD_COST_MODE_OFF, RecordRequired: true},
			want:     ConfigTeamSettings{Known: true, MailStrict: true, RecordRequired: true},
		},
		{
			settings: &protocol.ServiceSettings{RecordCost: protocol.RecordCostMode_RECORD_COST_MODE_ON, RecordRequired: true},
			want:     ConfigTeamSettings{Known: true, RecordCost: true, RecordRequired: true},
		},
	}
	configVersion := uint64(1)
	for _, c := range cases {
		configVersion += 1
		net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = c.settings
		if verdict := net.fold(net.owner, net.n, configVersion); !verdict.Accepted() {
			t.Fatalf("the base: %v", verdict.Refusal)
		}
		if honored := net.log.State().TeamSettings(); *honored != c.want {
			t.Errorf("%v: %+v", c.settings, honored)
		}
	}
	gate := net.everyReader()[2]
	if honored := gate.State().TeamSettings(); *honored != (ConfigTeamSettings{}) {
		t.Errorf("a rows-only reader: %+v", honored)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: net.header(), RepoId: testConfigId("directory repo").Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY,
	})
	if honored := net.log.State().TeamSettings(); !honored.Team || !honored.RecordCost {
		t.Errorf("a team network: %+v", honored)
	}
}

// A reader whose config.proto stops at directory = 6, as every build before the Settings fields does: it parses a
// ServiceSettings that sets all three, reads fields 1 to 6 as written, and keeps 7 to 9 as unknown fields through a
// re-sign, so an older admin's device filing other settings drops none of them; and this build takes an older writer's
// bytes with the three at their defaults, record_cost on.
func TestAnOlderReaderSkipsTheSettingsFields(t *testing.T) {
	older := protodesc.ToFileDescriptorProto(protocol.File_protocol_config_proto)
	older.EnumType = slices.DeleteFunc(older.EnumType, func(enum *descriptorpb.EnumDescriptorProto) bool {
		return enum.GetName() == "RecordCostMode"
	})
	for _, message := range older.MessageType {
		if message.GetName() == "ServiceSettings" {
			message.Field = slices.DeleteFunc(message.Field, func(field *descriptorpb.FieldDescriptorProto) bool {
				return 6 < field.GetNumber()
			})
		}
	}
	file, err := protodesc.NewFile(older, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	olderSettings := file.Messages().ByName("ServiceSettings")
	if olderSettings == nil || olderSettings.Fields().Len() != 6 || olderSettings.Fields().ByNumber(7) != nil {
		t.Fatal("the older ServiceSettings is not fields 1 to 6")
	}

	written := &protocol.ServiceSettings{
		TeamMail:          protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS,
		StaleLeafDays:     30,
		SelfAdmit:         protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF,
		WitnessBoundHours: 48,
		ScimSigner:        testConfigId("indexer").Bytes(),
		Directory:         &protocol.ServiceDirectorySettings{Runs: protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT},
		MailStrict:        true,
		RecordCost:        protocol.RecordCostMode_RECORD_COST_MODE_OFF,
		RecordRequired:    true,
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(written)
	if err != nil {
		t.Fatal(err)
	}
	read := dynamicpb.NewMessage(olderSettings)
	if err := proto.Unmarshal(encoded, read); err != nil {
		t.Fatalf("the older reader refused the head's settings: %v", err)
	}
	if len(read.GetUnknown()) == 0 {
		t.Fatal("the older reader holds no unknown field")
	}
	// what the older reader sees is fields 1 to 6 as written
	seen := proto.Clone(read)
	seen.ProtoReflect().SetUnknown(nil)
	seenBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(seen)
	if err != nil {
		t.Fatal(err)
	}
	firstSix := proto.Clone(written).(*protocol.ServiceSettings)
	firstSix.MailStrict, firstSix.RecordCost, firstSix.RecordRequired = false, protocol.RecordCostMode_RECORD_COST_MODE_UNSPECIFIED, false
	seenSettings := &protocol.ServiceSettings{}
	if err := proto.Unmarshal(seenBytes, seenSettings); err != nil || !proto.Equal(seenSettings, firstSix) {
		t.Fatalf("the older reader read %v: %v", seenSettings, err)
	}
	// its re-sign, as SaveDirectoryServiceSettings clones and signs, keeps the three
	resigned, err := proto.MarshalOptions{Deterministic: true}.Marshal(read)
	if err != nil {
		t.Fatal(err)
	}
	kept := &protocol.ServiceSettings{}
	if err := proto.Unmarshal(resigned, kept); err != nil || !proto.Equal(kept, written) {
		t.Fatalf("an older device's re-sign kept %v: %v", kept, err)
	}

	// an older writer's settings read here with the three at their defaults
	olderWritten := dynamicpb.NewMessage(olderSettings)
	olderWritten.Set(olderSettings.Fields().ByName("stale_leaf_days"), protoreflect.ValueOfUint32(30))
	olderBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(olderWritten)
	if err != nil {
		t.Fatal(err)
	}
	newer := &protocol.ServiceSettings{}
	if err := proto.Unmarshal(olderBytes, newer); err != nil || newer.GetStaleLeafDays() != 30 {
		t.Fatalf("an older writer's settings: %v %v", newer, err)
	}
	if err := CheckServiceSettings(newer); err != nil {
		t.Fatal(err)
	}
	if newer.GetMailStrict() || newer.GetRecordRequired() || newer.GetRecordCost() == protocol.RecordCostMode_RECORD_COST_MODE_OFF {
		t.Errorf("an older writer's settings read %v", newer)
	}
}
