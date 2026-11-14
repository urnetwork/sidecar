// ur evs versioning and ur evs ls -l (§11.7's cli row; R-EVS-20, D-EVS-38; EVS2-M10-16), through the daemon's evs
// client as ur evs's other parts go (cmd_evs_repo.go):
//
//	ur evs versioning <repo_id> (on|off) [--ref=<ref>] <path>...   every file the paths and globs name takes a new
//	                                                               version with the setting and its content
//	                                                               unchanged, in one push (EvsRepo.SetVersioning)
//	ur evs ls <repo_id> -l [--ref=<ref>] [<path>]                  each file's setting beside its name
//
// off keeps every version written while versioning was on and keeps only the newest from then on; on starts history at
// the version it writes. A file another write replaced while the command read it fails the push with its 409, which is
// printed as it is: the command never writes older content over a newer version. Outside §19.11's format2 gate off is
// refused and nothing is sent. Paths and globs are the person's own and go only between ur and its daemon on this
// device.

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control method ur evs versioning calls.
const urMethodEvsVersioning = "evs.versioning"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsVersioningMethods)
}

// What ur evs versioning asks: the repo, a ref's name, the paths and globs, and on or off.
type urEvsVersioningParams struct {
	RepoId     string   `json:"repo_id"`
	Ref        string   `json:"ref,omitempty"`
	Paths      []string `json:"paths"`
	Versioning string   `json:"versioning"`
}

// A listing's lines as ur evs ls prints them: its path and version, then each child, a directory with a slash, and
// with long each file's versioning setting before its name.
func urEvsListingLines(listing *sidecar.EvsListing, long bool) []string {
	lines := []string{fmt.Sprintf("%s at version %d", listingPath(listing.Path), listing.HeadVersion)}
	for _, entry := range listing.Entries {
		directory := entry.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
		name := string(entry.Name)
		if directory {
			name += "/"
		}
		switch {
		case !long:
			lines = append(lines, "  "+name)
		case directory:
			lines = append(lines, fmt.Sprintf("  %-5s  %s", "-", name))
		default:
			lines = append(lines, fmt.Sprintf("  %-5s  %s", sidecar.EvsVersioningName(entry.Versioning), name))
		}
	}
	return lines
}

// What a SetVersioning did, a line each.
func urEvsVersioningLines(result *sidecar.EvsSetVersioningResult, versioning string) []string {
	lines := []string{}
	for _, path := range result.Changed {
		lines = append(lines, fmt.Sprintf("versioning %s  %s", versioning, path))
	}
	for _, path := range result.Unchanged {
		lines = append(lines, fmt.Sprintf("already %s     %s", versioning, path))
	}
	if len(result.Changed) == 0 {
		return append(lines, "nothing changed")
	}
	return append(lines, fmt.Sprintf("%d file(s) at ref version %d", len(result.Changed), result.Version))
}

// The method over target, when it hosts a Sidecar.
func urEvsVersioningMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	evs, ok := target.(urEvsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodEvsVersioning,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urEvsVersioningParams{}
			if err := decodeUrParams(call, params); err != nil {
				return nil, err
			}
			_, repo, _, err := urEvsRepoOf(evs, &urEvsRepoParams{RepoId: params.RepoId})
			if err != nil {
				return nil, err
			}
			result, err := repo.SetVersioning(ctx, &sidecar.EvsSetVersioningArgs{
				RefName: urEvsRefName(params.Ref), Patterns: params.Paths, Versioning: params.Versioning,
			})
			switch {
			case errors.Is(err, sidecar.ErrEvsVersionlessConflict):
				return nil, fmt.Errorf("a file was replaced while its content was read; nothing was written, run the command again: %w", err)
			case err != nil:
				return nil, err
			}
			return &urEvsRepoReply{Lines: urEvsVersioningLines(result, params.Versioning)}, nil
		},
	}}
}

// Runs ur evs versioning: its params from the options, and each line of the daemon's answer printed.
func runUrEvsVersioning(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urEvsVersioningParams{RepoId: urOptionString(options, "<repo_id>"), Versioning: sidecar.EvsVersioningOff}
	if _, err := sidecar.EvsGitRepoOf("id:" + params.RepoId); err != nil {
		return fmt.Errorf("%q is no repo id", params.RepoId)
	}
	if urOptionBool(options, "on") {
		params.Versioning = sidecar.EvsVersioningOn
	}
	// docopt gives an option a list wherever one of the command's patterns repeats it
	switch value := options["--ref"].(type) {
	case string:
		params.Ref = value
	case []string:
		if 0 < len(value) {
			params.Ref = value[0]
		}
	}
	if paths, ok := options["<path>"].([]string); ok {
		params.Paths = paths
	}
	if len(params.Paths) == 0 {
		return errors.New("ur evs versioning takes at least one path or glob")
	}
	reply := &urEvsRepoReply{}
	if err := cli.callDaemon(ctx, urMethodEvsVersioning, params, false, reply); err != nil {
		return err
	}
	for _, line := range reply.Lines {
		cli.printf("%s\n", line)
	}
	return nil
}
