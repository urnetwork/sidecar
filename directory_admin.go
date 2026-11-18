//go:build !ios_extension && !sidecar_http

// ur admin directory's root half (RECORD-M6-23; §16.11's Surfaces and admins rows, D-CORE-13, D-TEAM-28; readings 14
// of plan-RECORD-small-readings):
//
//	runs, workers  ServiceSettings.directory {runs, workers} filed into the config head by an Owner's or Admin's
//	               device, as the person confirmed it, through this network's config writer: the head's other
//	               settings kept as they stand, every reader checking the record's signer at the base naming the head
//	               (TEAM-M6-10 honors them from M6). A device that runs no config writer refuses
//	keep, searchable  a RetentionPolicy for the coordination and request classes (directory_retention.go's
//	               SetDirectoryRetention), a directory admin's act
//	window         the index window is format 2's (RECORD-M10-04; §16.11's Index and search block): refused before it
//	               with needs_format 2, nothing signed; from it a directory admin's confirmed act writes the next
//	               index settings version on the cards ref's index, 7 to 90 days (SetDirectoryIndexWindow)
//
// Nothing here runs from MCP or a hook: each call takes SidecarActConfirmed, which only a /dev/tty-confirmed control
// call or an app's UI gives.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The directory's index window waits for format 2 (plan-RECORD-small-readings #14): nothing was signed.
var ErrDirectoryWindowFormat = fmt.Errorf("%w: needs_format 2: the directory's index window is format 2's", ErrEvsFormatUnsupported)

// What ur admin directory changes in ServiceSettings.directory: a nil field keeps the head's value.
type DirectoryServiceSettingsChange struct {
	Runs    *protocol.DirectoryRunsMode
	Workers *protocol.DirectoryWorkersMode
}

// Files ServiceSettings.directory into the config head, signed by this device: see the file's header's runs row.
// Answers the settings as filed.
func (self *Sidecar) SaveDirectoryServiceSettings(ctx context.Context, change *DirectoryServiceSettingsChange, origin SidecarActOrigin) (*protocol.ServiceDirectorySettings, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	if change == nil || (change.Runs == nil && change.Workers == nil) {
		return nil, errors.New("a directory settings change sets runs or workers")
	}
	if change.Runs != nil {
		switch *change.Runs {
		case protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_AUTO, protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT,
			protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF:
		default:
			return nil, fmt.Errorf("runs is auto, prompt or off, not %d", *change.Runs)
		}
	}
	if change.Workers != nil {
		switch *change.Workers {
		case protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_ON, protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_OFF:
		default:
			return nil, fmt.Errorf("workers is on or off, not %d", *change.Workers)
		}
	}
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok {
		return nil, ErrAgentPlanNoState
	}
	writer := authority.client.Writer()
	if writer == nil {
		return nil, errors.New("no config writer runs for this network on this device")
	}
	var filed *protocol.ServiceDirectorySettings
	_, err := writer.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
		current, _, err := head.ServiceSettings()
		if err != nil {
			return nil, err
		}
		settings := &protocol.ServiceSettings{}
		if current != nil {
			settings = proto.Clone(current).(*protocol.ServiceSettings)
		}
		directory := settings.GetDirectory()
		if directory == nil {
			directory = &protocol.ServiceDirectorySettings{}
		}
		if change.Runs != nil {
			directory.Runs = *change.Runs
		}
		if change.Workers != nil {
			directory.Workers = *change.Workers
		}
		settings.Directory = directory
		signed, err := configSignRecord(writer.args.Sign, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings)
		if err != nil {
			return nil, err
		}
		filed = proto.Clone(directory).(*protocol.ServiceDirectorySettings)
		return head.WithFile(ConfigHeadServiceSettingsPath, signed)
	})
	if err != nil {
		return nil, err
	}
	return filed, nil
}

// ServiceSettings.directory as this device honors it now, with §16.11's defaults, for ur admin directory to show;
// false where it opens no config head.
func (self *Sidecar) DirectoryServiceSettings() (*ConfigDirectorySettings, bool, error) {
	state, err := self.configState()
	if err != nil {
		return nil, false, err
	}
	settings, known := state.DirectorySettings()
	return settings, known, nil
}

// A window write no person confirmed, or one asked under a harness: nothing was signed.
var ErrDirectoryIndexUnconfirmed = errors.New("directory index window: not confirmed by a person")

// What ur admin directory --window asks (§16.11's settings row).
type DirectoryIndexWindowArgs struct {
	// The window's days, within DirectoryIndexSettings' WindowMinDays and WindowMaxDays.
	WindowDays uint32
	// A person confirmed the command on /dev/tty or in an app's UI (§5.8).
	Confirmed bool
	// The caller has a harness process among its ancestors: refused.
	HarnessAncestor bool
}

// What a window write did.
type DirectoryIndexWindow struct {
	WindowDays uint32
	// The index roots that took the settings, and whether a write waits at the storage limit.
	RootCount int
	Waiting   bool
}

// Sets the directory's index window, a directory admin's confirmed act: see directory_index.go's settings row. Refuses,
// with nothing signed, an unconfirmed call, a window outside the directory's days, a device that is no directory
// admin, a directory before format 2 (ErrDirectoryWindowFormat, needs_format 2) and a client whose evs binding writes
// no index settings. A window applies from the next bucket.
func (self *Sidecar) SetDirectoryIndexWindow(ctx context.Context, args *DirectoryIndexWindowArgs) (*DirectoryIndexWindow, error) {
	if args == nil || !args.Confirmed || args.HarnessAncestor {
		return nil, ErrDirectoryIndexUnconfirmed
	}
	client := self.Directory()
	if client == nil {
		return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", ErrDirectoryNone)
	}
	return client.SetIndexWindow(ctx, args.WindowDays)
}

// SetDirectoryIndexWindow's write, once a person confirmed it.
func (self *DirectoryClient) SetIndexWindow(ctx context.Context, windowDays uint32) (*DirectoryIndexWindow, error) {
	if self.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	if err := self.indexSettings().CheckWindowDays(windowDays); err != nil {
		return nil, err
	}
	auth := self.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return nil, ErrDirectoryNone
	}
	admin, _, err := self.directoryAdmin(auth)
	if err != nil {
		return nil, err
	}
	if !admin {
		return nil, ErrDirectoryEraseNotAdmin
	}
	if !self.Format2() {
		return nil, ErrDirectoryWindowFormat
	}
	binding, ok := self.boundCards().(DirectoryCardsIndexSettings)
	if !ok {
		return nil, ErrDirectoryIndexUnbound
	}
	result, err := binding.SetIndexWindow(ctx, directoryId, windowDays)
	window := &DirectoryIndexWindow{WindowDays: windowDays}
	if result != nil {
		window.RootCount = len(result.Roots)
	}
	if errors.Is(err, ErrEvsIndexWaits) {
		window.Waiting = true
		return window, nil
	}
	if err != nil {
		return nil, err
	}
	return window, nil
}
