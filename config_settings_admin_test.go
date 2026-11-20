//go:build !ios_extension && !sidecar_http

// ur admin settings' root half (config_settings_admin.go): only a person's confirmation files the Settings fields, never
// MCP, a hook or an unconfirmed call; only an Owner's or Admin's standing device signs them, the rule every reader holds
// the head's record to, a member's device refused before anything is signed; and a change keeps the head's other
// settings, record_cost written as its explicit value.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A pointer to value, for a change's fields.
func testServiceSettingsBool(value bool) *bool {
	return &value
}

// Every origin but a person's confirmation is refused before anything is read, whatever the change, so record_required
// is never set through MCP; a confirmed call with nothing to change, or with no verified state, signs nothing either.
func TestSaveServiceSettingsRefusesEveryOriginButAPersons(t *testing.T) {
	ctx := context.Background()
	change := &ServiceSettingsChange{RecordRequired: testServiceSettingsBool(true)}
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := (&Sidecar{}).SaveServiceSettings(ctx, change, origin); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	if _, err := (&Sidecar{}).SaveServiceSettings(ctx, &ServiceSettingsChange{}, SidecarActConfirmed); err == nil || errors.Is(err, ErrSidecarActMode) {
		t.Errorf("an empty change: %v", err)
	}
	if _, err := (&Sidecar{}).SaveServiceSettings(ctx, change, SidecarActConfirmed); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Errorf("no verified state: %v", err)
	}
}

// The writer's check is the readers' rule: an Owner's and an Admin's device may sign, an IT admin's, a network admin's
// and a member's may not, nor a device the state does not admit, each as configHeadRecordSignedByAdmin judges its
// signature.
func TestServiceSettingsSignerIsTheReadersRule(t *testing.T) {
	team := newTestConfigTeam(t)
	itAdmin, networkAdmin := testConfigId("it admin"), testConfigId("network admin")
	team.admitMember(team.owner, itAdmin, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	team.admitMember(team.owner, networkAdmin, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	itLaptop, networkLaptop := team.device("it laptop", itAdmin), team.device("network laptop", networkAdmin)
	team.admitDevice(team.owner, itLaptop, 0)
	team.admitDevice(team.owner, networkLaptop, 0)
	roles := team.adminSet(0)
	roles.ItAdmins = [][]byte{itAdmin.Bytes()}
	roles.NetworkAdmins = [][]byte{networkAdmin.Bytes()}
	_, setId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, roles)
	if verdict := team.cosign(team.adminB, setId); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	member := team.admitMemberDevice("plain")
	state := team.log.State()
	settings := &protocol.ServiceSettings{RecordCost: protocol.RecordCostMode_RECORD_COST_MODE_OFF, RecordRequired: true}
	for _, c := range []struct {
		name   string
		device testConfigDevice
		ok     bool
	}{
		{name: "an Owner's device", device: team.owner, ok: true},
		{name: "an Admin's device", device: team.adminB, ok: true},
		{name: "an IT admin's device", device: itLaptop, ok: false},
		{name: "a network admin's device", device: networkLaptop, ok: false},
		{name: "a member's device", device: member, ok: false},
	} {
		err := configServiceSettingsSigner(state, c.device.sidecarId)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrServiceSettingsSigner)) {
			t.Errorf("%s: %v", c.name, err)
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(team.sign(c.device, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings), signed); err != nil {
			t.Fatal(err)
		}
		if readerErr := configHeadRecordSignedByAdmin(state, signed, bridge.SignedType_SIGNED_SERVICE_SETTINGS); (readerErr == nil) != (err == nil) {
			t.Errorf("%s: the writer says %v, a reader %v", c.name, err, readerErr)
		}
	}
	if err := configServiceSettingsSigner(state, testConfigId("never admitted")); !errors.Is(err, ErrServiceSettingsSigner) {
		t.Errorf("a device the state does not admit: %v", err)
	}
}

// One Sidecar of a member of the client world's network, admitted under its own identity key, reading the world's
// client: what ur admin settings runs on.
func testServiceSettingsSidecar(t *testing.T, world *testConfigClientWorld, label string, memberId Id) (*Sidecar, *ConfigClient) {
	t.Helper()
	net := world.net
	device := net.device(label, memberId)
	running := newTestCleanupSidecar(t, net.networkId, device.sidecarId)
	admit := net.admission(device, nil, false, 0, 0)
	admit.IdentityPublicKey = bytes.Clone(running.currentIdentity().IdentityPublicKey)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)
	client := world.client(nil)
	world.publish()
	world.caughtUp(client)
	t.Cleanup(running.InstallAuthority(client.Authority()))
	return running, client
}

// On a Sidecar whose verified state names it a member's device, a confirmed change is refused before anything is
// signed; on an Owner's device the same change passes that check and stops only where no config writer runs here.
func TestSaveServiceSettingsRefusesAMembersDevice(t *testing.T) {
	ctx := context.Background()
	world := newTestConfigClientWorld(t)
	memberId, _ := world.net.consentedMember("plain member")
	member, _ := testServiceSettingsSidecar(t, world, "plain member laptop", memberId)
	owner, _ := testServiceSettingsSidecar(t, world, "owner laptop", world.net.ownerMemberId)
	change := &ServiceSettingsChange{RecordCost: testServiceSettingsBool(false), RecordRequired: testServiceSettingsBool(true)}
	if _, err := member.SaveServiceSettings(ctx, change, SidecarActConfirmed); !errors.Is(err, ErrServiceSettingsSigner) {
		t.Fatalf("a member's device: %v", err)
	}
	if _, err := owner.SaveServiceSettings(ctx, change, SidecarActConfirmed); err == nil || errors.Is(err, ErrServiceSettingsSigner) {
		t.Fatalf("an Owner's device with no config writer: %v", err)
	}
	for _, running := range []*Sidecar{member, owner} {
		if _, err := running.SaveServiceSettings(ctx, change, SidecarActMcp); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("through MCP: %v", err)
		}
	}
	honored, err := owner.TeamSettings()
	if err != nil || *honored != (ConfigTeamSettings{Known: true, RecordCost: true}) {
		t.Errorf("the settings as the Owner's device honors them: %+v %v", honored, err)
	}
}

// The head a test writer saves through: each edit applied to the head it holds, as ConfigWriter's SaveHead applies one
// to the newest head.
type testServiceSettingsHeads struct {
	head *ConfigHead
}

func (self *testServiceSettingsHeads) SaveHead(ctx context.Context, edit func(head *ConfigHead) (*ConfigHead, error)) (*bridge.AuthPin, error) {
	next, err := edit(self.head)
	if err != nil {
		return nil, err
	}
	self.head = next
	return &bridge.AuthPin{}, nil
}

// A change sets only its fields: the head's directory and witness bound stay as they were, record_cost is written as its
// explicit value, off then on, and every head it leaves holds a ServiceSettings an Owner's device signed, which readers
// take.
func TestServiceSettingsChangeKeepsTheHeadsOtherFields(t *testing.T) {
	ctx := context.Background()
	net := newTestConfigNet(t)
	existing := &protocol.ServiceSettings{
		WitnessBoundHours: 48,
		Directory:         &protocol.ServiceDirectorySettings{Runs: protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT},
	}
	head, err := testConfigHead(t, net).WithFile(ConfigHeadServiceSettingsPath, net.sign(net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, existing))
	if err != nil {
		t.Fatal(err)
	}
	heads := &testServiceSettingsHeads{head: head}
	sign := func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      bytes.Clone(body),
			SignerId:  net.owner.sidecarId.Bytes(),
			Signature: ed25519.Sign(net.owner.key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
	steps := []struct {
		change *ServiceSettingsChange
		want   *protocol.ServiceSettings
	}{
		{
			change: &ServiceSettingsChange{RecordCost: testServiceSettingsBool(false), RecordRequired: testServiceSettingsBool(true)},
			want: &protocol.ServiceSettings{
				WitnessBoundHours: 48, Directory: existing.GetDirectory(),
				RecordCost: protocol.RecordCostMode_RECORD_COST_MODE_OFF, RecordRequired: true,
			},
		},
		{
			change: &ServiceSettingsChange{RecordCost: testServiceSettingsBool(true), MailStrict: testServiceSettingsBool(true)},
			want: &protocol.ServiceSettings{
				WitnessBoundHours: 48, Directory: existing.GetDirectory(),
				MailStrict: true, RecordCost: protocol.RecordCostMode_RECORD_COST_MODE_ON, RecordRequired: true,
			},
		},
	}
	for i, step := range steps {
		filed, err := configSaveServiceSettings(ctx, heads, sign, step.change)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		held, signed, err := heads.head.ServiceSettings()
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(filed, step.want) || !proto.Equal(held, step.want) {
			t.Errorf("step %d filed %v and the head holds %v", i, filed, held)
		}
		if err := configHeadRecordSignedByAdmin(net.log.State(), signed, bridge.SignedType_SIGNED_SERVICE_SETTINGS); err != nil {
			t.Errorf("step %d: a reader refuses the head's settings: %v", i, err)
		}
	}
}
