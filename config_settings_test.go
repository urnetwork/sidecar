// §7.9's ServiceSettings on the test network: the bounds a head's settings keep, a full reader forking on a head outside
// them, the head-only values' defaults at a full reader and unknown at a rows-only one, scim_signer from rows, and
// FS-72's format-1 cases: a head holding VersioningRules or a ServiceSettings.directory compiles and applies with
// nothing taken from either.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// witness_bound_hours 0 or 24 to 168; known enum values; a scim_signer of none or a sidecar_id.
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
