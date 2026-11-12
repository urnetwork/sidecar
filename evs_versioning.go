//go:build !ios_extension

// A path's versioning on the client (§11.7's setting, choose and refused rows; R-EVS-20, D-EVS-35, D-EVS-42, D-EVS-61,
// FI-17, FS-68; EVS2-M10-14): the one function every writer calls for the versioning of the version it writes, so no
// writer picks a setting of its own and the planner (EVS2-M10-15) only follows it.
//
//	always 0   a git-mode ref, a creates-only ref (a record-class stream, a deposit or the erasure ref), a config or
//	           mailcfg repo, and any write while the network is outside §19.11's format2 gate (Format2Admitted), so
//	           a format-1 network never writes a format-2 value
//	explicit   the caller's "on" (0) or "off" (1), as §18.5 spells it: ur evs versioning, MCP's and the SDK's argument
//	newest     else the path's newest version's: a path keeps its setting, and an edit of the rules moves no
//	           existing path (owner decision 167)
//	reserved   else, for a new path, a reserved writer's fixed value: the search index 2, git-lfs's ur/lfs store 1,
//	           §15.7's s/model 1, the team directory's d/, r/ and q/ paths on its cards ref 1
//	rules      else ConfigState.VersioningFor with the repo id, the path and its plaintext size: the repo's own
//	           rules, else the network's, else the platform rule, a present set replacing the next entirely, so a
//	           path no rule matches is created versioned; never under .ur-index/ or on ur/lfs, whose writers are
//	           reserved; a reader that cannot open the network's rules writes versioned, which keeps every version
//	lock       a version that would be 1 in a locked repo is written 0, the path turning versioned at its next write,
//	           never refused to the caller; the index's 2 stands (owner decision 168)
//
// size_above_bytes compares the plaintext size, never the padded one, and the path string stays on the device (I-13):
// evs never reads rules, only each version's own setting.
//
// On every leg but ios_extension. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// The setting a write asks for, as §18.5 spells it: "" keeps the path's and gives a new path its rules' setting.
const (
	EvsVersioningKeepSetting = ""
	// every version kept: versioning 0
	EvsVersioningOn = "on"
	// versionless: versioning 1
	EvsVersioningOff = "off"
)

// A writer whose new paths take a fixed setting whatever the rules say (§11.7's choose row).
type EvsReservedWriter int

const (
	// No reserved writer: the rules decide a new path's setting.
	EvsReservedNone EvsReservedWriter = iota
	// §11.14's index files: versioning 2, under a lock too.
	EvsReservedIndex
	// 11.11's git-lfs store on ur/lfs: versioning 1.
	EvsReservedLfs
	// §15.7's mail component's s/model: versioning 1.
	EvsReservedMailModel
	// The team directory's d/, r/ and q/ paths on its cards ref, from its format 2 (§16.11): versioning 1.
	EvsReservedDirectory
)

// A setting that is no setting: something other than "", "on" or "off".
var ErrEvsVersioningSetting = errors.New("evs: a versioning setting other than on or off")

// What a write asks of the versions it writes (proposed; §11.20's Write, §18.5).
type EvsWriteOptions struct {
	// "", "on" or "off".
	Versioning string
	// The reserved writer the write is, EvsReservedNone for any other.
	Reserved EvsReservedWriter
}

// What EvsVersioningFor decides from: the write's options, the path, what stands there and what governs the repo.
type EvsVersioningArgs struct {
	Options *EvsWriteOptions
	RepoId  Id
	// The repo's kind, from the authorization state.
	RepoKind protocol.RepoKind
	// The ref's name bytes, its mode and whether it takes creates only (a record-class stream, a deposit ref or the
	// erasure ref).
	RefName     []byte
	RefMode     protocol.EvsRefMode
	CreatesOnly bool
	// The path, raw names joined by /, and its plaintext size in bytes.
	Path string
	Size uint64
	// The path's newest version as the plan read it; nil for a path that does not stand.
	Newest *protocol.EvsEntryVersion
	// Whether the newest verified state holds the repo locked (AclState.RepoLocked).
	Locked bool
	// Whether the network is in §19.11's format2 gate (EvsClient.Format2Admitted).
	Format2Admitted bool
	// The rules' setting for a new path (EvsConfigVersioningRules over ConfigState.VersioningFor); nil reads as no
	// rule, versioned.
	Rules func(repoId Id, filePath string, size uint64) (uint32, error)
}

// The versioning of the version a write makes: see the file header. ErrEvsVersioningSetting for a setting other than
// "", "on" or "off", or a reserved writer this file does not know; otherwise it decides and refuses nothing.
func EvsVersioningFor(args *EvsVersioningArgs) (uint32, error) {
	options := args.Options
	if options == nil {
		options = &EvsWriteOptions{}
	}
	switch options.Versioning {
	case EvsVersioningKeepSetting, EvsVersioningOn, EvsVersioningOff:
	default:
		return 0, fmt.Errorf("%w: %q", ErrEvsVersioningSetting, options.Versioning)
	}
	reserved, err := evsReservedVersioning(options.Reserved)
	if err != nil {
		return 0, err
	}
	kept := uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
	// always 0
	switch {
	case !args.Format2Admitted:
		return kept, nil
	case args.RefMode == protocol.EvsRefMode_EVS_REF_GIT, args.CreatesOnly:
		return kept, nil
	case args.RepoKind == protocol.RepoKind_REPO_KIND_CONFIG, args.RepoKind == protocol.RepoKind_REPO_KIND_MAILCFG:
		return kept, nil
	}
	setting := kept
	switch {
	case options.Versioning == EvsVersioningOn:
		setting = kept
	case options.Versioning == EvsVersioningOff:
		setting = uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	case args.Newest != nil:
		setting = args.Newest.GetVersioning()
	case options.Reserved != EvsReservedNone:
		setting = reserved
	case evsVersioningRuleExempt(args.RefName, args.Path):
		// only its reserved writers write there, and no rule applies
		setting = kept
	case args.Rules != nil:
		ruled, err := args.Rules(args.RepoId, args.Path, args.Size)
		switch {
		case errors.Is(err, ErrConfigVersioningUnknown), errors.Is(err, ErrConfigVersioningNotCovered):
			// rules this reader cannot open, or that cover no path here: versioned, which keeps every version
			setting = kept
		case err != nil:
			return 0, err
		default:
			setting = ruled
		}
	}
	if setting == uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) && args.Locked {
		// the lock: written 0, the path turning versioned at its next write (§11.7's refused row)
		setting = kept
	}
	return setting, nil
}

// A reserved writer's fixed setting.
func evsReservedVersioning(reserved EvsReservedWriter) (uint32, error) {
	switch reserved {
	case EvsReservedNone:
		return uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT), nil
	case EvsReservedIndex:
		return uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX), nil
	case EvsReservedLfs, EvsReservedMailModel, EvsReservedDirectory:
		return uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS), nil
	}
	return 0, fmt.Errorf("%w: reserved writer %d", ErrEvsVersioningSetting, reserved)
}

// Whether no rule applies to the path: under .ur-index/ on a file-mode ref, or on the ur/index or ur/lfs ref, which
// only §11.14's mechanisms and the git-lfs agent write (§11.7's setting row).
func evsVersioningRuleExempt(refName []byte, filePath string) bool {
	for _, reserved := range evsReservedRefNames {
		if bytes.Equal(refName, reserved) {
			return true
		}
	}
	names, err := evsPathNames(filePath)
	return err == nil && 0 < len(names) && bytes.Equal(names[0], evsReservedIndexDirectory)
}

// ConfigState.VersioningFor as EvsVersioningArgs.Rules reads it: the repo's own opened rules (repoRules, nil for none)
// over the network's and the platform rule.
func EvsConfigVersioningRules(state *ConfigState, repoRules *protocol.VersioningRules) func(repoId Id, filePath string, size uint64) (uint32, error) {
	return func(repoId Id, filePath string, size uint64) (uint32, error) {
		if state == nil {
			return 0, ErrConfigVersioningUnknown
		}
		return state.VersioningFor(repoId, filePath, size, repoRules)
	}
}
