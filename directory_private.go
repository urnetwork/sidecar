//go:build !sidecar_http && !ios_extension

// QD-748 (owner, 2026-11-12; §16.11's private row): a general or record repo marked private keeps that choice only in
// its private marker, which the team directory holds, so a create marked private files its RepoCreate only while the
// network's directory stands. Otherwise the repo would predate the directory, and §16.11's predating rule, which
// announces such a repo by the first of its admins' devices to sync it, would name it.
//
//	stands     the create goes on, and EvsClientArgs.RepoCreated writes the marker once the repo is active
//	none       a device that may file the directory, a config writer past base 1 in a network api puts in the team
//	           tier, files it first (TEAM-M6-10's FileTeamDirectory), catches up until its view shows it, and then goes
//	           on, so the repo's RepoCreate lands after the directory's; any other device refuses before anything is
//	           filed, naming the missing directory: a member's, and any device of a network outside the team tier,
//	           which files no directory (§7.5). A device cannot tell a personal network from a team outside the team
//	           tier, so a personal network refuses --private too, where it marks nothing: a personal network has no
//	           directory and announces no repo (owner decision 55)
//	deleted    a team whose directory is deleted takes no second one, so it refuses
//	unknown    a state, a tier, a view or an identity that cannot be read refuses, so a private repo is never filed
//	           where its marker could not follow
//
// Other kinds are announced only explicitly, by a person, so no rule names them on its own and they ask nothing. A
// create resumed by its id filed its RepoCreate already, and is not asked (EvsClient.CreateRepo).
//
// Nothing here creates, derives or unwraps a key. connect legs only: the page Worker creates no repo.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// What a private create reads and files the directory with.
type directoryPrivateRepoArgs struct {
	// The network's directory as the directory's view shows it now, false while none stands: DirectoryClient's.
	directory func() (Id, bool)
	// The newest verified config state, nil before one verifies (ConfigClient.State).
	state func() *ConfigState
	// Brings state, and the directory's view with it, to the log's tip (ConfigClient.CatchUp); nil for none.
	catchUp func(ctx context.Context) error
	// Whether api puts the network in the team tier, the only one in which a directory is filed (§7.5, §20.5).
	teamTier func(ctx context.Context) (bool, error)
}

// QD-748's check for a create of kind marked private, by client's device (see the file header): nil once the
// network's directory stands, filed first by this device where it may; ErrDirectoryPrivateNeedsDirectory, naming
// why, where it does not. A refusal files nothing of the repo, while a directory this device filed first stands
// whatever refuses after it, and a retry finds it.
func directoryReadyPrivateRepo(ctx context.Context, client *EvsClient, kind protocol.RepoKind, args *directoryPrivateRepoArgs) error {
	if !aclRepoKindGeneral(kind) {
		// announced only explicitly: nothing names it on its own
		return nil
	}
	if client == nil || args == nil || args.directory == nil || args.state == nil || args.teamTier == nil {
		return fmt.Errorf("%w: %w", ErrDirectoryPrivateNeedsDirectory, ErrTeamDirectoryUnwired)
	}
	if _, ok := args.directory(); ok {
		return nil
	}
	identity := client.args.Identity()
	if identity == nil {
		return fmt.Errorf("%w: this device has no identity", ErrDirectoryPrivateNeedsDirectory)
	}
	state := args.state()
	if state == nil || state.Base() == nil {
		return fmt.Errorf("%w: %w", ErrDirectoryPrivateNeedsDirectory, ErrTeamDirectoryNoState)
	}
	if existing := state.teamDirectoryRepo(); existing == nil {
		if !state.IsConfigWriter(identity.SidecarId) {
			return fmt.Errorf("%w: this network has none yet, and only a directory admin's device files it", ErrDirectoryPrivateNeedsDirectory)
		}
		team, err := args.teamTier(ctx)
		if err != nil {
			return fmt.Errorf("%w: whether this network is on the team tier did not read: %w", ErrDirectoryPrivateNeedsDirectory, err)
		}
		if !team {
			return fmt.Errorf("%w: this network has none, and is not on the team tier, the only one that files one; a personal network announces no repo", ErrDirectoryPrivateNeedsDirectory)
		}
	} else if _, live := NewDirectoryAuthView(state).Directory(); !live {
		return fmt.Errorf("%w: the team's directory is deleted", ErrDirectoryPrivateNeedsDirectory)
	}
	// files it, or finds the one that stands in the state, resuming it where this device filed it and a kill cut it
	// short
	file := &TeamDirectoryArgs{
		SidecarId:     identity.SidecarId,
		State:         args.state,
		CatchUp:       args.catchUp,
		FileStatement: client.args.FileStatement,
		CreateRepo:    client.CreateRepo,
	}
	if _, err := FileTeamDirectory(ctx, file); err != nil {
		return fmt.Errorf("%w: filing it: %w", ErrDirectoryPrivateNeedsDirectory, err)
	}
	if args.catchUp != nil {
		if err := args.catchUp(ctx); err != nil {
			return fmt.Errorf("%w: catching up to it: %w", ErrDirectoryPrivateNeedsDirectory, err)
		}
	}
	if _, ok := args.directory(); !ok {
		return fmt.Errorf("%w: it stands, and this device's view does not show it yet", ErrDirectoryPrivateNeedsDirectory)
	}
	return nil
}

// EvsClientArgs.PrivateCreate for this Sidecar: directoryReadyPrivateRepo over its directory client's view, its config
// client's state and catch-up, and api's tier for its network, filing through client. What is not bound yet refuses.
func (self *Sidecar) readyPrivateRepo(ctx context.Context, client *EvsClient, args *EvsCreateRepoArgs) error {
	if args == nil {
		return fmt.Errorf("%w: no repo", ErrDirectoryPrivateNeedsDirectory)
	}
	ready := &directoryPrivateRepoArgs{
		directory: func() (Id, bool) {
			directory, err := self.DirectoryClient()
			if err != nil {
				return Id{}, false
			}
			return directory.DirectoryId()
		},
		state:    func() *ConfigState { return nil },
		teamTier: self.teamTier,
	}
	if authority, ok := self.authority().(*ConfigAuthority); ok {
		ready.state = authority.client.State
		ready.catchUp = authority.client.CatchUp
	}
	return directoryReadyPrivateRepo(ctx, client, args.Kind, ready)
}

// Whether api puts this Sidecar's network in the team tier (GET /sidecar/limits).
func (self *Sidecar) teamTier(ctx context.Context) (bool, error) {
	if self.sidecarApi == nil {
		return false, errors.New("no api client")
	}
	limits, err := self.sidecarApi.Limits(ctx)
	if err != nil {
		return false, err
	}
	return limits.Tier == quotaTierTeam, nil
}
