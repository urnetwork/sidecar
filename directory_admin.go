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
//	window         the index window is format 2's: refused at M6 with needs_format 2, nothing signed
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
