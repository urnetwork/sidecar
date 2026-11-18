// ur admin directory (§16.11's Surfaces, admins and Index and search rows, D-CORE-13; plan-RECORD-small-readings #14;
// RECORD-M6-23, RECORD-M10-04):
//
//	ur admin directory [--runs=<runs>] [--workers=<workers>] [--window=<days>] [--keep=<days>] [--searchable=<days>]
//
// With no option it prints the team's settings as this device honors them. Otherwise it signs, only after a yes on
// /dev/tty, through a Confirm method: --runs and --workers file ServiceSettings.directory into the config head (an
// Owner's or Admin's device that runs the network's config writer), and --keep and --searchable a RetentionPolicy for
// the directory's coordination and request classes (a directory admin's device), --searchable within the directory's
// 7 to 400 days. --window sets the directory's index window, 7 to 90 days, a directory admin's act from format 2: a
// window outside its days refuses as the options parse, and a directory before format 2 refuses with needs_format 2
// before anything is asked or signed, by what the daemon's show method says of the directory; the daemon refuses the
// same again before it signs anything of the call. The daemon refuses a caller with a harness process among its
// ancestors, by the pid it read off the socket, and no MCP tool reaches any of it.

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur admin directory calls.
const (
	urMethodAdminDirectoryShow = "admin.directory.show"
	urMethodAdminDirectory     = "admin.directory"
)

var _ = registerUrAdminPart(&urAdminPart{
	word:  "directory",
	usage: []string{"  ur admin directory [--runs=<runs>] [--workers=<workers>] [--window=<days>] [--keep=<days>] [--searchable=<days>] [--network=<network>]"},
	run:   runUrAdminDirectory,
})

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAdminDirectoryMethods)
}

// What the methods take: a field left out changes nothing.
type urAdminDirectoryParams struct {
	Network string `json:"network,omitempty"`
	// auto, prompt or off.
	Runs string `json:"runs,omitempty"`
	// on or off.
	Workers string `json:"workers,omitempty"`
	// Days of the directory's index window, format 2's; 0 leaves it.
	WindowDays uint32 `json:"window_days,omitempty"`
	// Days, for the coordination and request classes; 0 with Retention set keeps entries with no limit.
	KeepDays       uint32 `json:"keep_days,omitempty"`
	SearchableDays uint32 `json:"searchable_days,omitempty"`
	Retention      bool   `json:"retention,omitempty"`
}

// The settings as this device honors them, and what a change filed.
type urAdminDirectoryReply struct {
	Runs    string `json:"runs,omitempty"`
	Workers string `json:"workers,omitempty"`
	// The head could not be opened here, so the settings are not known.
	Unknown bool `json:"unknown,omitempty"`
	// The retention entries a change wrote, one a class.
	RetentionEntries []sidecar.Id `json:"retention_entries,omitempty"`
	// Whether this device's directory is at format 2, so it takes an index window.
	WindowReady bool `json:"window_ready,omitempty"`
	// The index window a change wrote, the index roots that took it, and whether the write waits at the storage limit.
	WindowDays    uint32 `json:"window_days,omitempty"`
	WindowRoots   int    `json:"window_roots,omitempty"`
	WindowWaiting bool   `json:"window_waiting,omitempty"`
}

// ServiceSettings.directory's runs as the head carries it.
func urAdminDirectoryRuns(text string) (protocol.DirectoryRunsMode, error) {
	switch text {
	case "auto":
		return protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_AUTO, nil
	case "prompt":
		return protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT, nil
	case "off":
		return protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF, nil
	}
	return 0, fmt.Errorf("--runs is auto, prompt or off, not %q", text)
}

// ServiceSettings.directory's workers as the head carries it.
func urAdminDirectoryWorkers(text string) (protocol.DirectoryWorkersMode, error) {
	switch text {
	case "on":
		return protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_ON, nil
	case "off":
		return protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_OFF, nil
	}
	return 0, fmt.Errorf("--workers is on or off, not %q", text)
}

// A mode's name as ur prints it.
func urAdminDirectoryModeName(name string) string {
	name = strings.ToLower(name)
	if index := strings.LastIndex(name, "_mode_"); 0 <= index {
		return name[index+len("_mode_"):]
	}
	return name
}

// The admin directory methods over target's networks, when it hosts them.
func urAdminDirectoryMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if network, ok := target.(*urDaemonNetwork); !ok || network.daemon == nil {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodAdminDirectoryShow,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				settings, known, err := call.Sidecar.DirectoryServiceSettings()
				if err != nil {
					return nil, err
				}
				directory := call.Sidecar.Directory()
				reply := &urAdminDirectoryReply{WindowReady: directory != nil && directory.Format2()}
				if !known {
					reply.Unknown = true
					return reply, nil
				}
				reply.Runs, reply.Workers = urAdminDirectoryModeName(settings.Runs.String()), urAdminDirectoryModeName(settings.Workers.String())
				return reply, nil
			},
		},
		{
			Name:    urMethodAdminDirectory,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urAdminDirectoryParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				if call.Sidecar.HarnessAncestor(ctx, urCallPid(call)) {
					return nil, errors.New("ur admin directory is refused under a harness process")
				}
				reply := &urAdminDirectoryReply{}
				if params.WindowDays != 0 {
					// first, so a directory before format 2 refuses the whole call with nothing signed
					window, err := call.Sidecar.SetDirectoryIndexWindow(ctx, &sidecar.DirectoryIndexWindowArgs{WindowDays: params.WindowDays, Confirmed: true})
					if err != nil {
						return nil, err
					}
					reply.WindowDays, reply.WindowRoots, reply.WindowWaiting = window.WindowDays, window.RootCount, window.Waiting
				}
				if params.Runs != "" || params.Workers != "" {
					change := &sidecar.DirectoryServiceSettingsChange{}
					if params.Runs != "" {
						runs, err := urAdminDirectoryRuns(params.Runs)
						if err != nil {
							return nil, err
						}
						change.Runs = &runs
					}
					if params.Workers != "" {
						workers, err := urAdminDirectoryWorkers(params.Workers)
						if err != nil {
							return nil, err
						}
						change.Workers = &workers
					}
					filed, err := call.Sidecar.SaveDirectoryServiceSettings(ctx, change, sidecar.SidecarActConfirmed)
					if err != nil {
						return nil, err
					}
					reply.Runs = urAdminDirectoryModeName(filed.GetRuns().String())
					reply.Workers = urAdminDirectoryModeName(filed.GetWorkers().String())
				}
				if params.Retention {
					refs, err := call.Sidecar.SetDirectoryRetention(ctx, &sidecar.DirectoryRetentionArgs{
						KeepDays: params.KeepDays, SearchableDays: params.SearchableDays, Confirmed: true,
					})
					for _, ref := range refs {
						reply.RetentionEntries = append(reply.RetentionEntries, ref.EntryId)
					}
					if err != nil {
						return reply, err
					}
				}
				return reply, nil
			},
		},
	}
}

// A days option: absent, and false, when not given.
func parseUrAdminDirectoryDays(options docopt.Opts, key string) (uint32, bool, error) {
	text := urOptionString(options, key)
	if text == "" {
		return 0, false, nil
	}
	days, err := strconv.ParseUint(strings.TrimSuffix(text, "d"), 10, 32)
	if err != nil {
		return 0, false, fmt.Errorf("%s is a count of days, not %q", key, text)
	}
	return uint32(days), true, nil
}

// The params the options ask for: a --window or a --searchable outside the directory's days refuses here, before
// anything is asked or signed.
func urAdminDirectoryParamsOf(options docopt.Opts) (*urAdminDirectoryParams, error) {
	params := &urAdminDirectoryParams{
		Network: urOptionString(options, "--network"),
		Runs:    urOptionString(options, "--runs"),
		Workers: urOptionString(options, "--workers"),
	}
	if params.Runs != "" {
		if _, err := urAdminDirectoryRuns(params.Runs); err != nil {
			return nil, err
		}
	}
	if params.Workers != "" {
		if _, err := urAdminDirectoryWorkers(params.Workers); err != nil {
			return nil, err
		}
	}
	index := sidecar.DefaultDirectoryIndexSettings()
	if window, windowSet, err := parseUrAdminDirectoryDays(options, "--window"); err != nil {
		return nil, err
	} else if windowSet {
		if err := index.CheckWindowDays(window); err != nil {
			return nil, err
		}
		params.WindowDays = window
	}
	keep, keepSet, err := parseUrAdminDirectoryDays(options, "--keep")
	if err != nil {
		return nil, err
	}
	searchable, searchableSet, err := parseUrAdminDirectoryDays(options, "--searchable")
	if err != nil {
		return nil, err
	}
	if searchableSet {
		if err := index.CheckSearchableDays(searchable); err != nil {
			return nil, err
		}
	}
	params.KeepDays, params.SearchableDays, params.Retention = keep, searchable, keepSet || searchableSet
	return params, nil
}

// Prints the settings, or signs the change after a yes on /dev/tty.
func runUrAdminDirectory(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, err := urAdminDirectoryParamsOf(options)
	if err != nil {
		return err
	}
	if params.WindowDays != 0 {
		// the window is format 2's: a directory before it refuses before anything is asked
		shown := &urAdminDirectoryReply{}
		if err := cli.callDaemon(ctx, urMethodAdminDirectoryShow, &urAdminDirectoryParams{Network: params.Network}, false, shown); err != nil {
			return err
		}
		if !shown.WindowReady {
			return sidecar.ErrDirectoryWindowFormat
		}
	}
	if params.Runs == "" && params.Workers == "" && !params.Retention && params.WindowDays == 0 {
		reply := &urAdminDirectoryReply{}
		if err := cli.callDaemon(ctx, urMethodAdminDirectoryShow, params, false, reply); err != nil {
			return err
		}
		if reply.Unknown {
			cli.printf("directory settings: not known here, since this device opens no config head\n")
			return nil
		}
		cli.printf("directory settings: runs %s, workers %s\n", reply.Runs, reply.Workers)
		return nil
	}
	changes := []string{}
	if params.WindowDays != 0 {
		changes = append(changes, fmt.Sprintf("index window of %d days", params.WindowDays))
	}
	if params.Runs != "" {
		changes = append(changes, "runs "+params.Runs)
	}
	if params.Workers != "" {
		changes = append(changes, "workers "+params.Workers)
	}
	if params.Retention {
		changes = append(changes, fmt.Sprintf("keep %s, searchable %s for coordination and request entries",
			urRecordRetentionDays(params.KeepDays), urRecordRetentionDays(params.SearchableDays)))
	}
	reply := &urAdminDirectoryReply{}
	question := fmt.Sprintf("Sign the team directory's %s?", strings.Join(changes, "; "))
	if err := urDirectoryConfirmedCall(ctx, cli, urMethodAdminDirectory, params, question, reply); err != nil {
		return err
	}
	switch {
	case reply.WindowWaiting:
		cli.printf("index window of %d days waits at the storage limit and is written when it clears\n", reply.WindowDays)
	case reply.WindowDays != 0:
		cli.printf("index window of %d days written on %d index root(s), from the next bucket\n", reply.WindowDays, reply.WindowRoots)
	}
	if reply.Runs != "" {
		cli.printf("ServiceSettings.directory filed: runs %s, workers %s\n", reply.Runs, reply.Workers)
	}
	for _, entryId := range reply.RetentionEntries {
		cli.printf("retention entry %s is in your stream of the directory\n", entryId)
	}
	return nil
}
