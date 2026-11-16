//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs store's settings file (§11.11's prune row; plan-EVS2-lfs-settings, QD-258; EVS2-M10-28): a versioned file
// `settings` at ur/lfs's root, one path component of those 8 bytes, which no object's 2-character first directory can
// be, written at versioning 0 in every repo though the store's objects are 1, as one inline record. Its body is
//
//	message EvsLfsSettings { uint32 window_days = 1; }
//
// marshaled deterministically and sealed as any file, so it needs no §2.8 row. Until evs.proto carries the message
// (design-records), the field is encoded and read here by its wire form, which is byte-equal to the message's
// deterministic marshal.
//
//	window   N is LfsPruneWindow (30 days) when the file is absent or window_days is 0; 1 to 6 read as the floor,
//	         LfsPruneWindowFloor (7 days); 7 or more as written. The tip check's 5-day freshness rests on N >= 7, so no
//	         value reads below the floor
//	signer   a version counts only if its push's signer held repo admin (§8.8) at its signed time in the state the
//	         reader holds; a version no admin signed alarms and the window reads LfsPruneWindow, which keeps content
//	write    `ur evs lfs window <days>` writes it, 7 to LfsWindowMaxDays (365), as the store's reserved writer at
//	         versioning 0
//
// Desktop legs only. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// The settings file's path on ur/lfs, an identifier.
const EvsLfsSettingsPath = "settings"

// A window the command refuses: under 7 days or past LfsWindowMaxDays.
var ErrEvsLfsWindowInvalid = errors.New("evs: a git-lfs prune window outside 7 to 365 days")

// EvsLfsSettings{window_days} as its deterministic marshal: field 1 a varint, absent for 0.
func EncodeEvsLfsSettings(windowDays uint32) []byte {
	if windowDays == 0 {
		return []byte{}
	}
	encoded := protowire.AppendTag(nil, 1, protowire.VarintType)
	return protowire.AppendVarint(encoded, uint64(windowDays))
}

// An EvsLfsSettings body's window_days: unknown fields skipped, as any proto reader does; bytes that do not parse are
// an error, which a prune reads as the default window.
func DecodeEvsLfsSettings(body []byte) (uint32, error) {
	windowDays := uint32(0)
	for rest := body; 0 < len(rest); {
		number, wireType, n := protowire.ConsumeTag(rest)
		if n < 0 {
			return 0, fmt.Errorf("%w: a git-lfs settings file's tag", ErrEvsPushInvalid)
		}
		rest = rest[n:]
		if number == 1 && wireType == protowire.VarintType {
			value, n := protowire.ConsumeVarint(rest)
			if n < 0 || uint64(^uint32(0)) < value {
				return 0, fmt.Errorf("%w: a git-lfs settings file's window_days", ErrEvsPushInvalid)
			}
			windowDays, rest = uint32(value), rest[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(number, wireType, rest)
		if n < 0 {
			return 0, fmt.Errorf("%w: a git-lfs settings file's field %d", ErrEvsPushInvalid, number)
		}
		rest = rest[n:]
	}
	return windowDays, nil
}

// N for window_days: see the file header.
func EvsLfsWindow(windowDays uint32, settings *EvsSettings) time.Duration {
	switch {
	case windowDays == 0:
		return settings.LfsPruneWindow
	case time.Duration(windowDays)*24*time.Hour < settings.LfsPruneWindowFloor:
		return settings.LfsPruneWindowFloor
	}
	return time.Duration(windowDays) * 24 * time.Hour
}

// The window the store's settings file sets, read now: the default when the file is absent, does not parse, or its
// newest version's signer did not hold repo admin by isAdmin (nil: none is checked, which only a test passes), the
// last alarming through alarm.
func (self *EvsLfsStore) Window(ctx context.Context, isAdmin func(signerId Id, signedAt time.Time) bool, alarm func(err error)) (time.Duration, error) {
	body := &bytes.Buffer{}
	info, err := self.repo.ReadHead(ctx, &EvsReadArgs{RefName: EvsLfsRefName, Path: EvsLfsSettingsPath, Fresh: true}, body)
	switch {
	case errors.Is(err, ErrEvsPathAbsent):
		return self.settings.LfsPruneWindow, nil
	case err != nil:
		return 0, err
	}
	if isAdmin != nil && !isAdmin(info.SignerSidecarId, info.Time) {
		if alarm != nil {
			alarm(fmt.Errorf("a git-lfs settings version %d no repo admin signed: the window reads its default", info.Version))
		}
		return self.settings.LfsPruneWindow, nil
	}
	windowDays, err := DecodeEvsLfsSettings(body.Bytes())
	if err != nil {
		if alarm != nil {
			alarm(err)
		}
		return self.settings.LfsPruneWindow, nil
	}
	return EvsLfsWindow(windowDays, self.settings), nil
}

// Writes the settings file with windowDays, 7 to LfsWindowMaxDays: `ur evs lfs window <days>`. A write that moved
// under it answers the planner's *EvsPathConflictError, and the command reads and writes again.
func (self *EvsLfsStore) SetWindow(ctx context.Context, windowDays uint32) (*EvsWritePathsResult, error) {
	if time.Duration(windowDays)*24*time.Hour < self.settings.LfsPruneWindowFloor || self.settings.LfsWindowMaxDays < windowDays {
		return nil, fmt.Errorf("%w: %d days", ErrEvsLfsWindowInvalid, windowDays)
	}
	write := &EvsPathWrite{
		Path:    EvsLfsSettingsPath,
		Content: bytes.NewReader(EncodeEvsLfsSettings(windowDays)),
		// versioning 0, though the store's objects are 1 (QD-258)
		Options: &EvsWriteOptions{Reserved: EvsReservedLfs, Versioning: EvsVersioningOn},
	}
	return self.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: EvsLfsRefName, Writes: []*EvsPathWrite{write}})
}
