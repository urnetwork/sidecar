//go:build !ios_extension

// QD-059's signed projection rows through a rows-only reader and a subsequent fold.
package sidecar

import (
	"bytes"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A gate exposes exactly the bindings its verified base carries. Both ways a writer obtains
// a later fold keep them, and callers cannot change them through either accessor.
func TestConfigVerifiedTeamScopeRows(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	rows := net.log.State().Rows()
	tagId := testConfigId("scope tag")
	rows.TeamScopes = []*bridge.TeamScopeRow{
		{Label: "alpha-unit", Owner: &bridge.TeamScopeRow_MemberId{MemberId: net.ownerMemberId.Bytes()}},
		{Label: "ops-unit", Owner: &bridge.TeamScopeRow_TagAtom{TagAtom: tagId.Bytes()}},
	}
	gate := net.apiAtTip()
	if _, ok := gate.State().TeamScope("alpha-unit"); ok {
		t.Fatal("an undeclared scope was present")
	}
	entry := net.makeBase(net.owner, rows, net.n, 2, 0)
	if verdicts, err := gate.ApplyRun([][]byte{entry}, net.rowsOnlySource()); err != nil || len(verdicts) != 1 || !verdicts[0].Accepted() {
		t.Fatalf("signed scope base: %v, %v", verdicts, err)
	}
	state := gate.State()
	member, ok := state.TeamScope("alpha-unit")
	if !ok || member.MemberId != net.ownerMemberId || member.TagId != (Id{}) {
		t.Fatalf("member scope: %+v", member)
	}
	if device, ok := state.TeamScopeForDevice(net.owner.sidecarId); !ok || device != member {
		t.Fatalf("owner device scope: %+v", device)
	}
	tag, ok := state.TeamScope("ops-unit")
	if !ok || tag.TagId != tagId || tag.MemberId != (Id{}) {
		t.Fatalf("tag scope: %+v", tag)
	}
	state.TeamScopeLabels()[0] = "changed"
	state.Rows().GetTeamScopes()[0].Label = "changed"
	if _, ok := state.TeamScope("changed"); ok || !slices.Equal(state.TeamScopeLabels(), []string{"alpha-unit", "ops-unit"}) {
		t.Fatal("changing an answer changed the verified base")
	}
	head := testConfigHead(t, net)
	fromBase, err := configCompileRowsFromRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []*ConfigCompileRows{ConfigCompileRowsOf(state), fromBase} {
		slices.Reverse(source.TeamScopes)
		compiled, err := CompileProjectionRows(head, source)
		if err != nil {
			t.Fatal(err)
		}
		folded := &bridge.ProjectionRows{}
		if err := proto.Unmarshal(compiled, folded); err != nil {
			t.Fatal(err)
		}
		if len(folded.TeamScopes) != 2 || folded.TeamScopes[0].GetLabel() != "alpha-unit" ||
			!bytes.Equal(folded.TeamScopes[0].GetMemberId(), net.ownerMemberId.Bytes()) ||
			!bytes.Equal(folded.TeamScopes[1].GetTagAtom(), tagId.Bytes()) {
			t.Fatalf("folded scope rows: %v", folded.TeamScopes)
		}
	}
}

// A signed base with an unusable or ambiguous binding is refused as a whole.
func TestConfigTeamScopeRejectsMalformedBindings(t *testing.T) {
	net := newTestConfigNet(t)
	valid := &bridge.TeamScopeRow{Label: "team-unit", Owner: &bridge.TeamScopeRow_MemberId{MemberId: net.ownerMemberId.Bytes()}}
	for _, scopes := range [][]*bridge.TeamScopeRow{
		{valid, valid},
		{{Label: "team-unit"}},
		{{Label: "nested.label", Owner: valid.Owner}},
		{{Label: "beta-unit", Owner: valid.Owner}},
		{{Label: "team-unit", Owner: &bridge.TeamScopeRow_MemberId{MemberId: make([]byte, len(Id{}))}}},
		{{Label: "team-unit", Owner: &bridge.TeamScopeRow_TagAtom{TagAtom: make([]byte, len(Id{}))}}},
	} {
		gate := net.apiAtTip()
		rows := net.log.State().Rows()
		rows.TeamScopes = scopes
		entry := net.makeBase(net.owner, rows, net.n, 2, 0)
		if verdicts, err := gate.ApplyRun([][]byte{entry}, net.rowsOnlySource()); err == nil && len(verdicts) == 1 && verdicts[0].Accepted() {
			t.Errorf("accepted malformed scope rows %v", scopes)
		}
	}
}

// A tagged device may belong to more than one declared scope. A single match is a binding;
// multiple matches must not degrade to the no-scope audience.
func TestConfigTeamScopeForDeviceRejectsAmbiguity(t *testing.T) {
	device := testConfigId("scope device")
	first, second := testConfigId("first tag"), testConfigId("second tag")
	state := &ConfigState{sidecars: map[Id]*bridge.SidecarRow{
		device: {TagIds: [][]byte{first.Bytes(), second.Bytes()}},
	}, teamScopes: []*bridge.TeamScopeRow{
		{Label: "scope-one", Owner: &bridge.TeamScopeRow_TagAtom{TagAtom: first.Bytes()}},
	}}
	if scope, ok := state.TeamScopeForDevice(device); !ok || scope.Label != "scope-one" || scope.TagId != first {
		t.Fatalf("one tag scope: %v, %t", scope, ok)
	}
	state.teamScopes = append(state.teamScopes, &bridge.TeamScopeRow{Label: "scope-two", Owner: &bridge.TeamScopeRow_TagAtom{TagAtom: second.Bytes()}})
	if scope, ok := state.TeamScopeForDevice(device); !ok || scope != (AclScope{}) {
		t.Fatalf("ambiguous scope: %v, %t", scope, ok)
	}
	if _, ok := state.TeamScopeForDevice(testConfigId("no device")); ok {
		t.Fatal("unknown device matched a scope")
	}
}
