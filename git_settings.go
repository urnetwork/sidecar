//go:build !ios_extension && !sidecar_http

// The bundled git's settings, DESIGN-COMPUTE §13's, which GIT's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultGitSettings, protocol
// and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the compute
// skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultGitSettings.
//
// GIT-M13-01 fills the worktree's limits (§13.4's workspace, modes and collisions rows, §13.7's limits) and the
// format limits its readers hold git's files to; GIT-M13-02 the fetch's state and promisor limits. Later GIT tasks add
// their own (diff, rename, output).
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

// DESIGN-COMPUTE §13, the bundled git on EVS: its porcelain, merge, stash, tag and grep.
type GitSettings struct {
	// §13.7's file limit: the largest blob a worktree checks out, the store reads whole or writes, and add takes:
	// 50 MiB. A larger one is refused before a byte of it is written. Non-positive refuses every non-empty blob.
	FileByteCount int64
	// §13.7's file count: the most entries a worktree's index holds, and so the most files a checkout writes:
	// 100,000. A tree past it is refused before anything is written. Non-positive refuses every non-empty tree.
	FileCount int
	// The largest tree, commit or tag the store reads into memory: 16 MiB, room for a directory of the 100,000 files
	// FileCount allows and a long imported message. Blobs are FileByteCount's. Non-positive refuses every such object.
	ObjectByteCount int64
	// The longest loose object header git writes, `<kind> <size>` and its NUL: 32 bytes, a format limit (a tag's
	// kind and twenty digits of size fit). A header past it is refused as no object's.
	ObjectHeaderByteCount int
	// The largest index the worktree reads: 64 MiB, room for FileCount entries with long paths.
	IndexByteCount int64
	// The largest .git/config read, for its user.* values and its repository format alone: 64 KiB.
	ConfigByteCount int64
	// The largest loose ref, HEAD among them, read: 4 KiB, far past an oid or a `ref: ` line.
	RefByteCount int64
	// The largest packed-refs file read, which only stock git writes in a worktree: 16 MiB.
	PackedRefsByteCount int64
	// The most symbolic refs one read follows before it refuses the chain: 5, git's SYMREF_MAXDEPTH.
	SymbolicRefHopCount int
	// The largest .gitignore or .git/info/exclude read: 100 MiB, git's own PATTERN_MAX_FILE_SIZE; a larger one is
	// passed over, as git passes it over with a warning.
	IgnoreFileByteCount int64
	// The most symbolic links one link's target may pass through as the checkout resolves it inside the worktree:
	// 40, Linux's MAXSYMLINKS. A target that needs more is checked out as a text file naming it, as one that leaves the
	// worktree is.
	SymlinkHopCount int

	// GIT-M13-02's fetch state. The largest kept replay state of one ref read back (.git/ur/refs/): 64 MiB, room for
	// a long history's tip moves, which a source's version is read against.
	ReplayStateByteCount int64
	// The largest of this git's own small files under .git/ur read back: the habits, the state and a promisor locator
	// (.git/ur/promised/): 64 KiB, far past any of them.
	StateFileByteCount int64
}

// The component's defaults, the only place one is set.
func DefaultGitSettings() *GitSettings {
	return &GitSettings{
		FileByteCount:         50 * 1024 * 1024,
		FileCount:             100000,
		ObjectByteCount:       16 * 1024 * 1024,
		ObjectHeaderByteCount: 32,
		IndexByteCount:        64 * 1024 * 1024,
		ConfigByteCount:       64 * 1024,
		RefByteCount:          4 * 1024,
		PackedRefsByteCount:   16 * 1024 * 1024,
		SymbolicRefHopCount:   5,
		IgnoreFileByteCount:   100 * 1024 * 1024,
		SymlinkHopCount:       40,
		ReplayStateByteCount:  64 * 1024 * 1024,
		StateFileByteCount:    64 * 1024,
	}
}
