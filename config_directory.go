//go:build !ios_extension

// The team directory's creation and its settings (TEAM-M6-10; D-TEAM-28, I-20, §8.8, §16.11):
//
//	create    after the config's first base, team-create's first Owner device files RepoCreate{repo_id, kind
//	          directory}, becoming the repo's admin beside every config writer, then places it, forms its group and
//	          activates it (EvsClient.CreateRepo); an admin device that finds a team network with none files it the
//	          same way. Only a config writer files it; api and readers refuse a second in a network, deleted or not,
//	          and api one outside the team tier, which readers cannot see, so of two filers exactly one directory
//	          lands and the other finds it and files nothing
//	resume    a directory this device filed whose placement, group or activation a kill cut short goes on where it
//	          stopped: evs answers a retried create and activation as the first, and gkm resumes the group's KF1
//	settings  ServiceSettings.directory {runs: auto | prompt | off (auto), workers: on | off (on)}, signed by an
//	          Owner or Admin (the head check's signer row), rides the config head alone and is honored from M6; a
//	          value this build does not know reads as off, announcing nothing, so a writer ahead of this reader never
//	          widens what it announces. A reader that cannot open the head, a rows-only one, knows none
//
// The directory's token scopes are ACL's AclExchangeScopes (§8.10's directory row). Which networks are teams is api's
// to say (the tier), never the log's, so a caller files only in a network it knows is a team.
//
// Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// No verified state to judge the directory at, or none past base 1, after which alone the directory is filed.
	ErrTeamDirectoryNoState = errors.New("team directory: no verified state past base 1")
	// This device is no config writer, which alone files the directory (§8.8).
	ErrTeamDirectoryNotWriter = errors.New("team directory: only a config writer files the directory")
	// No statement poster or repo creator is wired, so nothing is filed.
	ErrTeamDirectoryUnwired = errors.New("team directory: no statement poster or repo creator")
)

// A team network's directory settings as a device honors them: never an unspecified value.
type ConfigDirectorySettings struct {
	// auto, prompt or off.
	Runs protocol.DirectoryRunsMode
	// on or off.
	Workers protocol.DirectoryWorkersMode
}

// ServiceSettings.directory as the newest base's config head holds it, with §16.11's defaults, auto and on, where it
// is unset, and off for a value this build does not know; false at a reader that could not open the head.
func (self *ConfigState) DirectorySettings() (*ConfigDirectorySettings, bool) {
	settings, known := self.HeadSettings()
	if !known {
		return nil, false
	}
	directory := settings.GetDirectory()
	honored := &ConfigDirectorySettings{
		Runs:    protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_AUTO,
		Workers: protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_ON,
	}
	switch runs := directory.GetRuns(); runs {
	case protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_UNSPECIFIED:
	case protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_AUTO, protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT,
		protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF:
		honored.Runs = runs
	default:
		honored.Runs = protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF
	}
	switch workers := directory.GetWorkers(); workers {
	case protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_UNSPECIFIED:
	case protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_ON, protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_OFF:
		honored.Workers = workers
	default:
		honored.Workers = protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_OFF
	}
	return honored, true
}

// The directory's row in the state, live, deleted or shredded, nil for none: any one blocks a second RepoCreate.
func (self *ConfigState) teamDirectoryRepo() *protocol.AclRepo {
	acl, err := self.Acl()
	if err != nil {
		return nil
	}
	var found *protocol.AclRepo
	for _, repo := range acl.Rows().GetRepos() {
		if repo.GetKind() != protocol.RepoKind_REPO_KIND_DIRECTORY {
			continue
		}
		// readers refuse a second, so rows hold one; the lowest id names it alike everywhere if a writer lied
		if found == nil || bytes.Compare(repo.GetRepoId(), found.GetRepoId()) < 0 {
			found = repo
		}
	}
	return found
}

// Whether the sidecar, in a network its caller knows is a team, should file the directory now: the state is past
// base 1, holds no directory row, and the sidecar writes config heads (§8.8's RepoCreate row).
func TeamDirectoryDue(state *ConfigState, sidecarId Id) bool {
	return state != nil && state.Base() != nil && state.teamDirectoryRepo() == nil && state.IsConfigWriter(sidecarId)
}

// What FileTeamDirectory reads and files with: on a daemon, its ConfigClient and EvsClient.
type TeamDirectoryArgs struct {
	// This device's sidecar.
	SidecarId Id
	// The newest verified config state, nil before one verifies (ConfigClient.State).
	State func() *ConfigState
	// Brings State to the log's tip (ConfigClient.CatchUp), after a RepoCreate the log refused.
	CatchUp func(ctx context.Context) error
	// The core's poster (EvsClientArgs.FileStatement): signs the RepoCreate under a fresh header, posts it, and
	// answers once it lands or is refused.
	FileStatement EvsFileStatementFunction
	// Places, keys and activates a filed repo: EvsClient.CreateRepo, always called with ResumeRepoId.
	CreateRepo func(ctx context.Context, args *EvsCreateRepoArgs) (*EvsRepo, error)
}

// What FileTeamDirectory did.
type TeamDirectoryResult struct {
	// The network's directory.
	RepoId Id
	// This call filed its RepoCreate; false when the state already held one, this device's or another's.
	Filed bool
}

// Files the team network's directory from this device, or finds the one that stands (see the file header). A
// directory this device filed is resumed through CreateRepo until it is active; one another filed is left to its
// creator. Only a config writer past base 1 files; a RepoCreate the log refuses is answered by the directory that
// then stands, the race's winner, or by its refusal when none does.
func FileTeamDirectory(ctx context.Context, args *TeamDirectoryArgs) (*TeamDirectoryResult, error) {
	if args == nil || args.State == nil || args.FileStatement == nil || args.CreateRepo == nil {
		return nil, ErrTeamDirectoryUnwired
	}
	state := args.State()
	if state == nil || state.Base() == nil {
		return nil, ErrTeamDirectoryNoState
	}
	if existing := state.teamDirectoryRepo(); existing != nil {
		return resumeTeamDirectory(ctx, args, existing)
	}
	if !state.IsConfigWriter(args.SidecarId) {
		return nil, fmt.Errorf("%w: %s at %d", ErrTeamDirectoryNotWriter, args.SidecarId, state.Pin().GetVersion())
	}

	repoId := NewEvsRepoId()
	create := &protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY}
	testHookBarrier("team_directory.file.before", args.SidecarId.String())
	if err := args.FileStatement(ctx, bridge.SignedType_SIGNED_REPO_CREATE, create); err != nil {
		// another filer's may have landed first: the log refuses a second, and its directory answers this one
		if args.CatchUp != nil {
			if catchUpErr := args.CatchUp(ctx); catchUpErr != nil {
				return nil, errors.Join(fmt.Errorf("team directory: RepoCreate: %w", err), catchUpErr)
			}
		}
		if after := args.State(); after != nil {
			if existing := after.teamDirectoryRepo(); existing != nil {
				return resumeTeamDirectory(ctx, args, existing)
			}
		}
		return nil, fmt.Errorf("team directory: RepoCreate: %w", err)
	}
	testHookBarrier("team_directory.file.after", args.SidecarId.String())
	if _, err := args.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, ResumeRepoId: &repoId}); err != nil {
		return &TeamDirectoryResult{RepoId: repoId, Filed: true}, fmt.Errorf("team directory: the repo: %w", err)
	}
	return &TeamDirectoryResult{RepoId: repoId, Filed: true}, nil
}

// The directory that stands: resumed through CreateRepo where this device filed it and it is not deleted, else left
// as it is.
func resumeTeamDirectory(ctx context.Context, args *TeamDirectoryArgs, repo *protocol.AclRepo) (*TeamDirectoryResult, error) {
	repoId, err := IdFromBytes(repo.GetRepoId())
	if err != nil {
		return nil, fmt.Errorf("team directory: a row of %d bytes: %w", len(repo.GetRepoId()), err)
	}
	result := &TeamDirectoryResult{RepoId: repoId}
	deletion := repo.GetDeletion()
	deleted := deletion != nil && deletion.GetDeletedAt() != 0 && deletion.GetRestoredAt() == 0
	if deleted || !teamDirectoryCreatedBy(repo, args.SidecarId) {
		return result, nil
	}
	if _, err := args.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, ResumeRepoId: &repoId}); err != nil {
		return result, fmt.Errorf("team directory: resuming the repo: %w", err)
	}
	return result, nil
}

// Whether the sidecar filed the directory's RepoCreate: the admin row its creation wrote, which names the signer, while
// it stands; a removed creator resumes nothing, as when a removal took its row out (QD-743).
func teamDirectoryCreatedBy(repo *protocol.AclRepo, sidecarId Id) bool {
	for _, admin := range repo.GetAdmins() {
		if AclRepoAdminStands(admin) && bytes.Equal(admin.GetSidecarId(), sidecarId.Bytes()) && bytes.Equal(admin.GetSigner(), sidecarId.Bytes()) {
			return true
		}
	}
	return false
}
