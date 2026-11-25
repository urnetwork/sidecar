//go:build !ios_extension && !sidecar_http && !js

// Every spelling of .git a file tool refuses (DESIGN-COMPUTE §7.5, D-HARN-13, IC-7, §13.7): in the local profile only
// the bundled git writes a worktree's git directory, so a file tool refuses every path component that a file system
// could take as .git, in each spelling git itself refuses and more:
//
//   - case: .GIT, .Git (case-insensitive file systems; git's core.protectHFS and core.protectNTFS);
//   - NTFS: trailing dots and spaces (.git., .git ., .git...), an alternate data stream (.git::$INDEX_ALLOCATION), and
//     the 8.3 short name git~1 (git's is_ntfs_dotgit);
//   - HFS+: the code points HFS+ ignores, zero-width joiners and the bidirectional and shaping controls, anywhere in the
//     name (.g, U+200C, it; git's is_hfs_dotgit);
//   - Unicode folding: the name decomposed (NFKD), its combining marks and the ignorable code points dropped, and
//     case-folded, so a fullwidth .git (U+FF0E U+FF47 U+FF49 U+FF54) or a .git whose i is U+0130, an I with a dot
//     above, is refused too. Git refuses less than this; refusing more costs a model nothing it needs.
//
// A config an agent wrote there, core.fsmonitor among them, would run on the person's computer once their shell or
// editor opened the worktree (D-HARN-13), so a refusal here is a security check, never a convenience.

package sidecar

import (
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// The code points HFS+ ignores in a name (git's next_hfs_char).
func harnessHfsIgnorable(r rune) bool {
	switch {
	case 0x200c <= r && r <= 0x200f, 0x202a <= r && r <= 0x202e, 0x206a <= r && r <= 0x206f, r == 0xfeff:
		return true
	}
	return false
}

// Whether name, one path component, is .git or git~1 as NTFS reads it: then only spaces and periods, up to the end or
// a colon that begins a stream (git's is_ntfs_dotgit), compared without case.
func harnessDotGitNtfs(name string) bool {
	lower := strings.ToLower(name)
	rest := ""
	switch {
	case strings.HasPrefix(lower, ".git"):
		rest = lower[len(".git"):]
	case strings.HasPrefix(lower, "git~1"):
		rest = lower[len("git~1"):]
	default:
		return false
	}
	for _, r := range rest {
		if r == ':' {
			return true
		}
		if r != ' ' && r != '.' {
			return false
		}
	}
	return true
}

// name folded as the widest of the file systems would compare it: decomposed with compatibility (NFKD), its combining
// marks and HFS+'s ignorable code points dropped, then case-folded.
func harnessGitFold(name string) string {
	decomposed := norm.NFKD.String(name)
	stripped := strings.Map(func(r rune) rune {
		if harnessHfsIgnorable(r) || unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, decomposed)
	return cases.Fold().String(stripped)
}

// Whether component, one path component, is a spelling of .git a file tool refuses.
func harnessGitPathComponent(component string) bool {
	return harnessDotGitNtfs(component) || harnessDotGitNtfs(harnessGitFold(component))
}
