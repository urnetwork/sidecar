//go:build !ios_extension && !sidecar_http

// QD-1163's Team scope declarations: an Owner's or Admin's device files a label's first binding into the config head's
// ServiceSettings.team_scopes, a person's confirmation alone; compile writes the head's bindings as the rows' Team
// scopes, which every reader takes from a verified base and nothing else establishes; a head that drops or rebinds a
// binding its base holds forks the base, so a first binding never changes; a first binding names a member the log
// holds or a tag atom the head's tags table holds; a reader starting at a base holds its rows' scopes to its head's;
// and a policy naming a scope host validates only once a verified base holds its binding. Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network whose writer files Team scopes: its config net, a head that holds tag:ops in its tags table, the writer's
// heads and the owner's signature.
type testTeamScopeNet struct {
	net   *testConfigNet
	heads *testServiceSettingsHeads
	sign  ConfigSignFunction
	ops   Id
}

func newTestTeamScopeNet(t *testing.T) *testTeamScopeNet {
	t.Helper()
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	ops := testConfigId("tag ops")
	tags, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ConfigAtomTable{Atoms: []*protocol.ConfigAtomName{{Name: "ops", AtomId: ops.Bytes()}}})
	if err != nil {
		t.Fatal(err)
	}
	names, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ConfigNameTable{Names: []*protocol.ConfigName{{SidecarId: net.owner.sidecarId.Bytes(), Name: "laptop"}}})
	if err != nil {
		t.Fatal(err)
	}
	head, err := testConfigHead(t, net).WithFile(ConfigHeadTagsPath, tags)
	if err != nil {
		t.Fatal(err)
	}
	if head, err = head.WithFile(ConfigHeadNamesPath, names); err != nil {
		t.Fatal(err)
	}
	sign := func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      bytes.Clone(body),
			SignerId:  net.owner.sidecarId.Bytes(),
			Signature: ed25519.Sign(net.owner.key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
	return &testTeamScopeNet{net: net, heads: &testServiceSettingsHeads{head: head}, sign: sign, ops: ops}
}

// Files binding against the newest state.
func (self *testTeamScopeNet) save(binding *TeamScopeBinding) (AclScope, error) {
	return configSaveTeamScope(context.Background(), self.heads, self.sign, self.net.log.State(), binding, aclTestNow)
}

// The rows the writer's head compiles to over the newest state, or the compile's refusal.
func (self *testTeamScopeNet) compile(head *ConfigHead) (*bridge.ProjectionRows, error) {
	compiled, err := CompileProjectionRows(head, ConfigCompileRowsOf(self.net.log.State()))
	if err != nil {
		return nil, err
	}
	rows := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(compiled, rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// Publishes a base with rows at the next config version, as every reader then holds it.
func (self *testTeamScopeNet) publish(t *testing.T, rows *bridge.ProjectionRows) {
	t.Helper()
	state := self.net.log.State()
	if verdict := self.net.pushBase(self.net.owner, rows, self.net.n, state.Base().GetConfigVersion()+1, 0); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
}

// The head with its ServiceSettings replaced by settings, signed by the owner.
func (self *testTeamScopeNet) headWith(t *testing.T, settings *protocol.ServiceSettings) *ConfigHead {
	t.Helper()
	head, err := self.heads.head.WithFile(ConfigHeadServiceSettingsPath, self.net.sign(self.net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings))
	if err != nil {
		t.Fatal(err)
	}
	return head
}

// Every origin but a person's confirmation is refused before anything is read, and a confirmed call with no verified
// state signs nothing either.
func TestSaveTeamScopeRefusesEveryOriginButAPersons(t *testing.T) {
	ctx := context.Background()
	binding := &TeamScopeBinding{Label: "crew", MemberId: testConfigId("a member")}
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := (&Sidecar{}).SaveTeamScope(ctx, binding, origin); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	if _, err := (&Sidecar{}).SaveTeamScope(ctx, binding, SidecarActConfirmed); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Errorf("no verified state: %v", err)
	}
	if _, err := (&Sidecar{}).TeamScopes(); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Errorf("no verified state's scopes: %v", err)
	}
}

// A member scope and a tag scope are filed into the head's ServiceSettings in label order, every other setting kept,
// under an Owner's signature every reader takes; no reader holds either before a base does; the head compiles to
// rows holding both, which a verified base then carries to every reader's state, a member's device in its scope; and
// the next compile over that base keeps them.
func TestTeamScopeFirstBindingsReachReadersThroughAVerifiedBase(t *testing.T) {
	scopes := newTestTeamScopeNet(t)
	net := scopes.net
	kept, err := scopes.heads.head.WithFile(ConfigHeadServiceSettingsPath, net.sign(net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS,
		&protocol.ServiceSettings{WitnessBoundHours: 48, MailStrict: true}))
	if err != nil {
		t.Fatal(err)
	}
	scopes.heads.head = kept
	member, err := scopes.save(&TeamScopeBinding{Label: "crew", MemberId: net.ownerMemberId})
	if err != nil || member != (AclScope{Label: "crew", MemberId: net.ownerMemberId}) {
		t.Fatalf("the member scope: %+v, %v", member, err)
	}
	tag, err := scopes.save(&TeamScopeBinding{Label: "alpha", Tag: "tag:ops"})
	if err != nil || tag != (AclScope{Label: "alpha", TagId: scopes.ops}) {
		t.Fatalf("the tag scope: %+v, %v", tag, err)
	}
	settings, signed, err := scopes.heads.head.ServiceSettings()
	if err != nil {
		t.Fatal(err)
	}
	want := []*bridge.TeamScopeRow{{Label: "alpha", TagAtom: scopes.ops.Bytes()}, {Label: "crew", MemberId: net.ownerMemberId.Bytes()}}
	if !slices.EqualFunc(settings.GetTeamScopes(), want, func(a *bridge.TeamScopeRow, b *bridge.TeamScopeRow) bool { return proto.Equal(a, b) }) ||
		settings.GetWitnessBoundHours() != 48 || !settings.GetMailStrict() {
		t.Fatalf("the head's settings: %v", settings)
	}
	if err := configHeadRecordSignedByAdmin(net.log.State(), signed, bridge.SignedType_SIGNED_SERVICE_SETTINGS); err != nil {
		t.Fatalf("a reader refuses the head's settings: %v", err)
	}
	if _, found := net.log.State().TeamScope("crew"); found {
		t.Fatal("a head's binding reached a reader before any base held it")
	}

	rows, err := scopes.compile(scopes.heads.head)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(rows.GetTeamScopes(), want, func(a *bridge.TeamScopeRow, b *bridge.TeamScopeRow) bool { return proto.Equal(a, b) }) {
		t.Fatalf("the compiled scopes: %v", rows.GetTeamScopes())
	}
	scopes.publish(t, rows)
	gate := net.apiAtTip()
	for _, state := range []*ConfigState{net.log.State(), gate.State()} {
		if got, found := state.TeamScope("crew"); !found || got != member {
			t.Errorf("crew: %+v", got)
		}
		if got, found := state.TeamScope("alpha"); !found || got != tag {
			t.Errorf("alpha: %+v", got)
		}
		if got, found := state.TeamScopeForDevice(net.owner.sidecarId); !found || got != member {
			t.Errorf("the owner's device: %+v", got)
		}
	}
	again, err := scopes.compile(scopes.heads.head)
	if err != nil || !proto.Equal(again, rows) {
		t.Errorf("the next compile over the base: %v", err)
	}
}

// A head that drops a binding its base holds, has no ServiceSettings at all, or binds a held label to another member
// or to a tag forks the base: compile refuses it, so no reader holds it, and the writer refuses to file one, whether the
// state already holds the label or only the head does; a binding of the same owner again is refused too, as is a second
// label for an owner; a new binding beside the held ones compiles.
func TestTeamScopeBindingNeverChanges(t *testing.T) {
	scopes := newTestTeamScopeNet(t)
	net := scopes.net
	other, _ := net.consentedMember("other member")
	if _, err := scopes.save(&TeamScopeBinding{Label: "crew", MemberId: net.ownerMemberId}); err != nil {
		t.Fatal(err)
	}
	// the head holds crew while no base does: the writer reads the head it edits
	for _, binding := range []*TeamScopeBinding{
		{Label: "crew", MemberId: other},
		{Label: "crew", MemberId: net.ownerMemberId},
		{Label: "crew", Tag: "ops"},
		{Label: "crew-two", MemberId: net.ownerMemberId},
	} {
		if _, err := scopes.save(binding); !errors.Is(err, ErrTeamScopeBound) {
			t.Errorf("%+v over a head holding crew: %v", binding, err)
		}
	}
	rows, err := scopes.compile(scopes.heads.head)
	if err != nil {
		t.Fatal(err)
	}
	scopes.publish(t, rows)
	// the state holds crew now
	if _, err := scopes.save(&TeamScopeBinding{Label: "crew", MemberId: other}); !errors.Is(err, ErrTeamScopeBound) {
		t.Errorf("a reassignment over a base holding crew: %v", err)
	}

	for name, settings := range map[string]*protocol.ServiceSettings{
		"a dropped binding":    {},
		"another member":       {TeamScopes: []*bridge.TeamScopeRow{{Label: "crew", MemberId: other.Bytes()}}},
		"a tag":                {TeamScopes: []*bridge.TeamScopeRow{{Label: "crew", TagAtom: scopes.ops.Bytes()}}},
		"another label for it": {TeamScopes: []*bridge.TeamScopeRow{{Label: "crow", MemberId: net.ownerMemberId.Bytes()}}},
	} {
		if _, err := scopes.compile(scopes.headWith(t, settings)); !errors.Is(err, ErrConfigTeamScopeRebound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bare, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scopes.compile(bare); !errors.Is(err, ErrConfigTeamScopeRebound) {
		t.Errorf("a head with no ServiceSettings: %v", err)
	}
	beside := scopes.headWith(t, &protocol.ServiceSettings{TeamScopes: []*bridge.TeamScopeRow{
		{Label: "crew", MemberId: net.ownerMemberId.Bytes()}, {Label: "zeta", MemberId: other.Bytes()},
	}})
	if rows, err := scopes.compile(beside); err != nil || len(rows.GetTeamScopes()) != 2 {
		t.Errorf("a new binding beside the held one: %v", err)
	}
}

// A first binding names a member the log holds or a tag atom the head's tags table holds: compile refuses any other,
// and the writer refuses a member the state does not hold, a tag the head declares no owners of, and a binding naming
// both owners or neither, before it signs.
func TestTeamScopeFirstBindingNamesAnOwnerOfTheNetwork(t *testing.T) {
	scopes := newTestTeamScopeNet(t)
	for name, scope := range map[string]*bridge.TeamScopeRow{
		"a stranger": {Label: "crew", MemberId: testConfigId("never a member").Bytes()},
		"a lost tag": {Label: "crew", TagAtom: testConfigId("tag gone").Bytes()},
	} {
		if _, err := scopes.compile(scopes.headWith(t, &protocol.ServiceSettings{TeamScopes: []*bridge.TeamScopeRow{scope}})); !errors.Is(err, ErrConfigTeamScopeOwnerUnknown) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, binding := range map[string]*TeamScopeBinding{
		"a stranger": {Label: "crew", MemberId: testConfigId("never a member")},
		"a lost tag": {Label: "crew", Tag: "tag:gone"},
		"both":       {Label: "crew", MemberId: scopes.net.ownerMemberId, Tag: "ops"},
		"neither":    {Label: "crew"},
	} {
		before := scopes.heads.head
		if _, err := scopes.save(binding); !errors.Is(err, ErrTeamScopeOwner) || scopes.heads.head != before {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A label meets §12.5's rules for a scope label and none of §12.7's refused owners, the brand rules, the head's client
// names or a host the policy publishes, so the writer signs none of these; ServiceSettings holds its bindings in label
// order with no label twice, each of QD-059's shape, or a head check refuses it.
func TestTeamScopeLabelRules(t *testing.T) {
	scopes := newTestTeamScopeNet(t)
	net := scopes.net
	for _, label := range []string{"", "www", "word-1234", "b", "mta-sts", "urnetw0rk", "Crew", "xn--crew", "a.b", "-crew", "crew-", "laptop",
		strings.Repeat("c", 64)} {
		before := scopes.heads.head
		if _, err := scopes.save(&TeamScopeBinding{Label: label, MemberId: net.ownerMemberId}); !errors.Is(err, ErrTeamScopeLabel) || scopes.heads.head != before {
			t.Errorf("label %q: %v", label, err)
		}
	}

	// a host the policy publishes: the state's rows give the owner's devices publish and listen on blog
	world := newAclCompileWorld("published")
	world.members, world.sidecars = net.log.State().Rows().GetMembers(), net.log.State().Rows().GetSidecars()
	world.setPolicy(t, `{"grants":[
		{"src":["autogroup:member"],"dst":["dns:blog"],"allow":["publish"]},
		{"src":["autogroup:member"],"dst":["sock:tls/443/blog"],"allow":["listen"]}
	]}`)
	state := configCopyState(net.log.State())
	state.aclRows = world.compile(t)
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(acl.PublishedNames(aclTestNow), func(name *AclPublishedName) bool { return name.Host == "blog" }) {
		t.Fatal("the policy publishes no blog")
	}
	if _, err := configSaveTeamScope(context.Background(), scopes.heads, scopes.sign, state, &TeamScopeBinding{Label: "blog", MemberId: net.ownerMemberId}, aclTestNow); !errors.Is(err, ErrTeamScopeLabel) {
		t.Errorf("a published host: %v", err)
	}
	if _, err := configSaveTeamScope(context.Background(), scopes.heads, scopes.sign, state, &TeamScopeBinding{Label: "crew", MemberId: net.ownerMemberId}, aclTestNow); err != nil {
		t.Errorf("a free label beside the published host: %v", err)
	}

	member := net.ownerMemberId.Bytes()
	for name, settings := range map[string]*protocol.ServiceSettings{
		"out of order":   {TeamScopes: []*bridge.TeamScopeRow{{Label: "zeta", MemberId: member}, {Label: "alpha", TagAtom: scopes.ops.Bytes()}}},
		"a label twice":  {TeamScopes: []*bridge.TeamScopeRow{{Label: "crew", MemberId: member}, {Label: "crew", TagAtom: scopes.ops.Bytes()}}},
		"no owner":       {TeamScopes: []*bridge.TeamScopeRow{{Label: "crew"}}},
		"two owners":     {TeamScopes: []*bridge.TeamScopeRow{{Label: "crew", MemberId: member, TagAtom: scopes.ops.Bytes()}}},
		"a reserved one": {TeamScopes: []*bridge.TeamScopeRow{{Label: "www", MemberId: member}}},
	} {
		if err := CheckServiceSettings(settings); !errors.Is(err, ErrConfigRule) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A reader starting at a base holds the base's rows' Team scopes to its head's ServiceSettings, exactly: rows that add,
// lose or rebind one are refused as a mismatch, so even a first base's scopes come from a signed head.
func TestConfigAnchorHoldsTheRowsTeamScopesToItsHead(t *testing.T) {
	scopes := newTestTeamScopeNet(t)
	net := scopes.net
	records := []ConfigFoldRecord{}
	for n := uint64(1); n <= net.n; n += 1 {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(net.entries[n-1], entry); err != nil {
			t.Fatal(err)
		}
		records = append(records, configFoldRecordOf(&configKeptEntry{n: n, entry: entry, verdict: net.log.keptEntryOrEmpty(n).verdict}))
	}
	declared := []*bridge.TeamScopeRow{{Label: "crew", MemberId: net.ownerMemberId.Bytes()}}
	head, err := testConfigHead(t, net, records).WithFile(ConfigHeadServiceSettingsPath, net.sign(net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS,
		&protocol.ServiceSettings{TeamScopes: declared}))
	if err != nil {
		t.Fatal(err)
	}
	anchor := func(scopes []*bridge.TeamScopeRow) error {
		// rows as compile writes them, its settings always present, so never empty bytes
		rows, err := proto.Marshal(&bridge.ProjectionRows{Settings: &bridge.ProjectionSettings{}, TeamScopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		_, err = CheckConfigBase(head, &ConfigHeadCheck{
			Header:         &bridge.ProjectionHeader{FoldedThrough: net.n},
			GenesisChain:   bridge.GenesisChain(net.signedGenesis),
			FoldedFrom:     net.n + 1,
			FirstPrevChain: net.chain,
			Rows:           rows,
		}, nil)
		return err
	}
	if err := anchor(declared); err != nil {
		t.Fatalf("rows holding the head's scopes: %v", err)
	}
	for name, rows := range map[string][]*bridge.TeamScopeRow{
		"none":      nil,
		"another":   {{Label: "crew", MemberId: testConfigId("another member").Bytes()}},
		"one more":  {{Label: "crew", MemberId: net.ownerMemberId.Bytes()}, {Label: "zeta", MemberId: net.ownerMemberId.Bytes()}},
		"a new one": {{Label: "crow", MemberId: net.ownerMemberId.Bytes()}},
	} {
		if err := anchor(rows); !errors.Is(err, ErrConfigHeadMismatch) {
			t.Errorf("rows holding %s: %v", name, err)
		}
	}
}

// A scope host in a policy validates only through a verified base's binding: before any binding, and while only the
// head the writer filed declares one, the writer's plan refuses a listen on a crew host; once a base holds the
// binding the same plan passes, its preview naming crew's member. A grant naming the host, or a directory's answer,
// establishes nothing.
func TestAclScopeHostValidatesOnlyThroughAVerifiedBinding(t *testing.T) {
	scopes := newTestTeamScopeNet(t)
	net := scopes.net
	writer := newTestAclWriterDevice(t)
	source := []byte(`{"grants":[{"src":["autogroup:member"],"dst":["sock:tls/443/*.crew"],"allow":["listen"]}]}`)
	invalid := &AclValidationError{}
	if _, err := writer.aclWriterPlan(t.Context(), source, nil, net.log.State(), scopes.heads.head); !errors.As(err, &invalid) {
		t.Fatalf("no binding: %v", err)
	}
	if _, err := scopes.save(&TeamScopeBinding{Label: "crew", MemberId: net.ownerMemberId}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.aclWriterPlan(t.Context(), source, nil, net.log.State(), scopes.heads.head); !errors.As(err, &invalid) {
		t.Fatalf("a head's binding no base holds: %v", err)
	}
	rows, err := scopes.compile(scopes.heads.head)
	if err != nil {
		t.Fatal(err)
	}
	scopes.publish(t, rows)
	plan, err := writer.aclWriterPlan(t.Context(), source, nil, net.log.State(), scopes.heads.head)
	if err != nil {
		t.Fatalf("a verified binding: %v", err)
	}
	if !slices.ContainsFunc(plan.Preview.Resolutions, func(row AclSaveResolution) bool {
		return row.Kind == "member_scope" && row.Text == "crew" && row.Id == net.ownerMemberId
	}) {
		t.Errorf("the preview: %+v", plan.Preview.Resolutions)
	}
}
