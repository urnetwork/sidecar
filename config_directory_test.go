//go:build !ios_extension

// The team directory's creation and ServiceSettings.directory (config_directory.go; TEAM-M6-10, D-TEAM-28) on the test
// team network, whose log judges each RepoCreate at its position as api and every reader do.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One device's FileTeamDirectory over the test network: its poster signs and sequences at the tip, its state is the
// reader's unless the test holds a stale one, and each CreateRepo it asks is recorded.
type testTeamDirectoryFiler struct {
	net    *testConfigNet
	device testConfigDevice
	// the state the device last read, until a catch-up; nil reads the reader's newest
	stale        *ConfigState
	posted       []ConfigVerdict
	createdRepos []*EvsCreateRepoArgs
	createError  error
}

func (self *testTeamDirectoryFiler) args() *TeamDirectoryArgs {
	return &TeamDirectoryArgs{
		SidecarId: self.device.sidecarId,
		State: func() *ConfigState {
			if self.stale != nil {
				return self.stale
			}
			return self.net.log.State()
		},
		CatchUp: func(ctx context.Context) error {
			self.stale = nil
			return nil
		},
		FileStatement: func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
			create := body.(*protocol.RepoCreate)
			create.Header = self.net.header()
			verdict := self.net.post(self.device, signedType, create)
			self.posted = append(self.posted, verdict)
			return verdict.Refusal
		},
		CreateRepo: func(ctx context.Context, args *EvsCreateRepoArgs) (*EvsRepo, error) {
			self.createdRepos = append(self.createdRepos, args)
			return nil, self.createError
		},
	}
}

// The state's directory rows.
func testTeamDirectories(state *ConfigState) []*protocol.AclRepo {
	acl, err := state.Acl()
	if err != nil {
		return nil
	}
	directories := []*protocol.AclRepo{}
	for _, repo := range acl.Rows().GetRepos() {
		if repo.GetKind() == protocol.RepoKind_REPO_KIND_DIRECTORY {
			directories = append(directories, repo)
		}
	}
	return directories
}

// Two filers who each found none: the first's RepoCreate lands and it creates the repo; the second's is refused at its
// position, and it answers with the first's directory, filing nothing more and creating nothing.
func TestTwoDirectoryFilersMakeOneDirectory(t *testing.T) {
	team := newTestConfigTeam(t)
	before := team.log.State()
	first := &testTeamDirectoryFiler{net: team.testConfigNet, device: team.owner}
	second := &testTeamDirectoryFiler{net: team.testConfigNet, device: team.adminB, stale: before}
	if !TeamDirectoryDue(before, team.owner.sidecarId) || !TeamDirectoryDue(before, team.adminB.sidecarId) {
		t.Fatal("neither filer finds the directory due")
	}

	filed, err := FileTeamDirectory(context.Background(), first.args())
	if err != nil || !filed.Filed {
		t.Fatalf("the first filer: %+v %v", filed, err)
	}
	if len(first.createdRepos) != 1 || *first.createdRepos[0].ResumeRepoId != filed.RepoId ||
		first.createdRepos[0].Kind != protocol.RepoKind_REPO_KIND_DIRECTORY {
		t.Fatalf("the first filer's repo: %+v", first.createdRepos)
	}

	lost, err := FileTeamDirectory(context.Background(), second.args())
	if err != nil || lost.Filed || lost.RepoId != filed.RepoId {
		t.Fatalf("the second filer: %+v %v", lost, err)
	}
	if len(second.posted) != 1 || second.posted[0].Accepted() || !errors.Is(second.posted[0].Refusal, ErrConfigRule) {
		t.Fatalf("the second RepoCreate: %+v", second.posted)
	}
	if len(second.createdRepos) != 0 {
		t.Error("the second filer created a repo")
	}
	directories := testTeamDirectories(team.log.State())
	if len(directories) != 1 || Id(directories[0].GetRepoId()) != filed.RepoId {
		t.Fatalf("directories %v", directories)
	}
	if TeamDirectoryDue(team.log.State(), team.adminB.sidecarId) {
		t.Error("the directory is still due once one stands")
	}
	team.everyReaderAgrees()
}

// An admin device that finds a team with no directory files it, becoming its creator; a plain member's device files
// nothing; and nothing is filed on a state before base 1.
func TestAnAdminDeviceThatFindsNoDirectoryFilesIt(t *testing.T) {
	team := newTestConfigTeam(t)
	member := team.admitMemberDevice("plain")
	if TeamDirectoryDue(team.log.State(), member.sidecarId) {
		t.Error("a plain member's device finds the directory due")
	}
	plain := &testTeamDirectoryFiler{net: team.testConfigNet, device: member}
	if _, err := FileTeamDirectory(context.Background(), plain.args()); !errors.Is(err, ErrTeamDirectoryNotWriter) {
		t.Fatalf("a plain member's device: %v", err)
	}
	if len(plain.posted) != 0 || len(plain.createdRepos) != 0 {
		t.Fatal("a plain member's device filed")
	}

	genesisOnly := &testTeamDirectoryFiler{net: team.testConfigNet, device: team.owner, stale: team.statesAt[0]}
	if _, err := FileTeamDirectory(context.Background(), genesisOnly.args()); !errors.Is(err, ErrTeamDirectoryNoState) {
		t.Fatalf("before base 1: %v", err)
	}
	if _, err := FileTeamDirectory(context.Background(), &TeamDirectoryArgs{SidecarId: team.owner.sidecarId}); !errors.Is(err, ErrTeamDirectoryUnwired) {
		t.Fatalf("with nothing wired: %v", err)
	}

	admin := &testTeamDirectoryFiler{net: team.testConfigNet, device: team.adminB}
	filed, err := FileTeamDirectory(context.Background(), admin.args())
	if err != nil || !filed.Filed {
		t.Fatalf("the admin device: %+v %v", filed, err)
	}
	directories := testTeamDirectories(team.log.State())
	if len(directories) != 1 || !teamDirectoryCreatedBy(directories[0], team.adminB.sidecarId) {
		t.Fatalf("the admin's directory: %v", directories)
	}
	// its creator and every config writer administer it: the owner's device too
	acl, err := team.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []testConfigDevice{team.adminB, team.owner} {
		access := acl.EvsAccess(AclSidecarSubject(device.sidecarId), filed.RepoId, AclTokenAudienceEvs, time.UnixMilli(team.timeMs))
		if !access.Rights.Has(AclEvsAdmin) {
			t.Errorf("%s does not administer the directory: %+v", device.sidecarId, access)
		}
	}
	team.everyReaderAgrees()
}

// A directory this device filed, cut short after its RepoCreate, is resumed through CreateRepo at its id; one another
// device filed, or one deleted, is left as it is.
func TestADirectoryThisDeviceFiledResumes(t *testing.T) {
	team := newTestConfigTeam(t)
	cut := &testTeamDirectoryFiler{net: team.testConfigNet, device: team.owner, createError: ErrEvsRepoKeying}
	filed, err := FileTeamDirectory(context.Background(), cut.args())
	if !errors.Is(err, ErrEvsRepoKeying) || filed == nil || !filed.Filed {
		t.Fatalf("a create cut short: %+v %v", filed, err)
	}

	again := &testTeamDirectoryFiler{net: team.testConfigNet, device: team.owner}
	resumed, err := FileTeamDirectory(context.Background(), again.args())
	if err != nil || resumed.Filed || resumed.RepoId != filed.RepoId {
		t.Fatalf("the resume: %+v %v", resumed, err)
	}
	if len(again.posted) != 0 || len(again.createdRepos) != 1 || *again.createdRepos[0].ResumeRepoId != filed.RepoId {
		t.Fatalf("the resume filed %d and created %+v", len(again.posted), again.createdRepos)
	}

	other := &testTeamDirectoryFiler{net: team.testConfigNet, device: team.adminB}
	found, err := FileTeamDirectory(context.Background(), other.args())
	if err != nil || found.Filed || found.RepoId != filed.RepoId || len(other.createdRepos) != 0 {
		t.Fatalf("another device: %+v %v %+v", found, err, other.createdRepos)
	}
}

// ServiceSettings.directory: §16.11's defaults, auto and on, with no settings or none set; the head's values when set;
// off for a value this build does not know; unknown at a rows-only reader.
func TestDirectorySettingsDefaultsApplied(t *testing.T) {
	net := newTestConfigNet(t)
	honored, known := net.log.State().DirectorySettings()
	if !known || honored.Runs != protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_AUTO || honored.Workers != protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_ON {
		t.Fatalf("the defaults: %+v %v", honored, known)
	}

	cases := []struct {
		settings    *protocol.ServiceSettings
		wantRuns    protocol.DirectoryRunsMode
		wantWorkers protocol.DirectoryWorkersMode
	}{
		{
			settings:    &protocol.ServiceSettings{WitnessBoundHours: 24},
			wantRuns:    protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_AUTO,
			wantWorkers: protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_ON,
		},
		{
			settings:    &protocol.ServiceSettings{Directory: &protocol.ServiceDirectorySettings{Runs: protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT, Workers: protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_OFF}},
			wantRuns:    protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT,
			wantWorkers: protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_OFF,
		},
		{
			settings:    &protocol.ServiceSettings{Directory: &protocol.ServiceDirectorySettings{Runs: protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF}},
			wantRuns:    protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF,
			wantWorkers: protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_ON,
		},
		{
			settings:    &protocol.ServiceSettings{Directory: &protocol.ServiceDirectorySettings{Runs: 9, Workers: 9}},
			wantRuns:    protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF,
			wantWorkers: protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_OFF,
		},
	}
	configVersion := uint64(1)
	for _, c := range cases {
		configVersion += 1
		net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = c.settings
		if verdict := net.fold(net.owner, net.n, configVersion); !verdict.Accepted() {
			t.Fatalf("the base: %v", verdict.Refusal)
		}
		honored, known := net.log.State().DirectorySettings()
		if !known || honored.Runs != c.wantRuns || honored.Workers != c.wantWorkers {
			t.Errorf("%v: %+v %v", c.settings, honored, known)
		}
	}
	gate := net.everyReader()[2]
	if _, known := gate.State().DirectorySettings(); known {
		t.Error("a rows-only reader knows the directory settings")
	}
}

// ServiceSettings, the directory's with it, is signed only by an Owner's or Admin's standing device (§7.9's signer row
// for ServiceSettings, which the head check applies): an IT admin's, a network admin's and a member's are refused.
func TestDirectorySettingsSignedOnlyByAnOwnerOrAdmin(t *testing.T) {
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
	if state.Member(itAdmin).GetRole() != bridge.MemberRole_MEMBER_ROLE_IT_ADMIN || state.Member(networkAdmin).GetRole() != bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN {
		t.Fatalf("roles %s and %s", state.Member(itAdmin).GetRole(), state.Member(networkAdmin).GetRole())
	}

	settings := &protocol.ServiceSettings{Directory: &protocol.ServiceDirectorySettings{Runs: protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT}}
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
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(team.sign(c.device, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings), signed); err != nil {
			t.Fatal(err)
		}
		if err := configHeadRecordSignedByAdmin(state, signed, bridge.SignedType_SIGNED_SERVICE_SETTINGS); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
