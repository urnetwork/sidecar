//go:build !ios_extension && !sidecar_http

// The bundled git's path safety (DESIGN-COMPUTE §13.7, IC-7, D-GIT-1; GIT-M13-01): every path a tree, an index or a
// command names is held to what stock git's fsck --strict and verify_path refuse after their 2025-2026 advisories,
// before anything is written for it, and a little more:
//
//	form      a path is names joined by '/': not empty, no NUL, no empty name (a doubled or trailing '/'), no '.' or
//	          '..' name, not absolute (a leading '/'), no drive prefix (C:, which Windows reads as absolute)
//	.git      no name that a file system could take as .git: git's is_ntfs_dotgit (any case, trailing dots and spaces,
//	          an alternate data stream after a colon, the 8.3 name git~1) and is_hfs_dotgit (the code points HFS+
//	          ignores, anywhere in the name), and beyond git the name decomposed (NFKD), its combining marks and those
//	          code points dropped and case-folded, as the Harness's file tools fold it (harness_git_path.go), so a
//	          fullwidth .git or one whose i is U+0130 is refused too
//	backslash refused in every name on every leg, beyond fsck: Windows reads it as a separator, so a\..\x would be a
//	          traversal there, and a repo is shared across legs
//	symlinks  a link named .gitmodules in any of git's spellings (fsck's gitmodulesSymlink); a path through a symlink
//	          is the worktree's to refuse as it writes, since only the file system says which names are links
//	          (git_worktree.go)
//
// A refusal is a GitPathError: its text names the rule, never the path, since an error may reach a log (I-13); the
// porcelain shows the path to whoever asked from the error's Path.
//
// Package-level functions, safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// A path the bundled git will not hold.
var ErrGitPathUnsafe = errors.New("git: a path ur git refuses")

// A refused path and the rule that refused it.
type GitPathError struct {
	// The path as given, for the porcelain to show the person or agent who named it; never in Error's text.
	Path string
	// The rule, in words.
	Rule string
}

// The rule alone (I-13).
func (self *GitPathError) Error() string {
	return fmt.Sprintf("%s: %s", ErrGitPathUnsafe.Error(), self.Rule)
}

// Wraps ErrGitPathUnsafe.
func (self *GitPathError) Unwrap() error {
	return ErrGitPathUnsafe
}

// Holds a path of mode (a tree entry's, 0 for a path whose mode is not known yet) to the file header's rules: nil, or
// a GitPathError.
func gitCheckPath(path string, mode uint32) error {
	refuse := func(rule string) error {
		return &GitPathError{Path: path, Rule: rule}
	}
	switch {
	case path == "":
		return refuse("an empty path")
	case strings.IndexByte(path, 0) != -1:
		return refuse("a NUL in the path")
	case strings.HasPrefix(path, "/"):
		return refuse("an absolute path")
	case gitDrivePrefix(path):
		return refuse("a drive prefix, which Windows reads as absolute")
	case strings.IndexByte(path, '\\') != -1:
		return refuse("a backslash, which Windows reads as a separator")
	}
	names := strings.Split(path, "/")
	for index, name := range names {
		switch {
		case name == "":
			return refuse("an empty name: a doubled or trailing slash")
		case name == ".":
			return refuse("a . name")
		case name == "..":
			return refuse("a .. name")
		case gitDotGitName(name):
			return refuse("a .git name, in some spelling a file system reads as .git")
		}
		if index == len(names)-1 && mode == EvsGitModeSymlink && gitDotGitmodulesName(name) {
			return refuse("a symbolic link named .gitmodules")
		}
	}
	return nil
}

// Whether a path opens with a drive letter and a colon.
func gitDrivePrefix(path string) bool {
	return 2 <= len(path) && path[1] == ':' && ('a' <= path[0] && path[0] <= 'z' || 'A' <= path[0] && path[0] <= 'Z')
}

// Whether one name is .git as NTFS, HFS+ or the widest fold reads it (see the file header).
func gitDotGitName(name string) bool {
	return gitNtfsDotGit(name) || gitHfsDotGeneric(name, "git") || gitNtfsDotGit(gitFoldName(name))
}

// Whether one name is .gitmodules as NTFS or HFS+ reads it, git's is_ntfs_dotgitmodules and is_hfs_dotgitmodules.
func gitDotGitmodulesName(name string) bool {
	return gitNtfsDotGeneric(name, "gitmodules", "gi7eba") || gitHfsDotGeneric(name, "gitmodules")
}

// git's is_ntfs_dotgit over one name: .git or git~1, in any case, then only spaces and periods to the end or a colon.
func gitNtfsDotGit(name string) bool {
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
	return gitOnlySpacesAndPeriods(rest)
}

// Whether rest holds only spaces and periods up to its end or a colon, which opens an alternate data stream.
func gitOnlySpacesAndPeriods(rest string) bool {
	for index := 0; index < len(rest); index += 1 {
		switch rest[index] {
		case ':':
			return true
		case ' ', '.':
		default:
			return false
		}
	}
	return true
}

// git's is_ntfs_dot_generic over one name: `.<needle>` in any case then only spaces and periods, the 8.3 short name
// of the needle's first six letters with ~1 to ~4, or the hashed fallback short name `<prefix>~<digits>`.
func gitNtfsDotGeneric(name string, needle string, shortPrefix string) bool {
	if strings.HasPrefix(name, ".") && len(needle) < len(name) && strings.EqualFold(name[1:1+len(needle)], needle) {
		return gitOnlySpacesAndPeriods(name[1+len(needle):])
	}
	if 8 <= len(name) && strings.EqualFold(name[:6], needle[:6]) && name[6] == '~' && '1' <= name[7] && name[7] <= '4' {
		return gitOnlySpacesAndPeriods(name[8:])
	}
	if len(name) < 8 {
		return false
	}
	sawTilde := false
	index := 0
	for ; index < 8; index += 1 {
		c := name[index]
		switch {
		case sawTilde:
			if c < '0' || '9' < c {
				return false
			}
		case c == '~':
			index += 1
			if len(name) <= index || name[index] < '1' || '9' < name[index] {
				return false
			}
			sawTilde = true
		case 6 <= index, 0x80 <= c:
			return false
		case unicode.ToLower(rune(c)) != rune(shortPrefix[index]):
			return false
		}
	}
	return gitOnlySpacesAndPeriods(name[index:])
}

// git's is_hfs_dot_generic over one name: a period then the needle, compared without case, every code point HFS+
// ignores skipped, then the end. Malformed UTF-8 is no .git, as git reads it.
func gitHfsDotGeneric(name string, needle string) bool {
	rest := name
	// the next code point HFS+ does not ignore, or -1 at the end or at malformed UTF-8
	next := func() rune {
		for 0 < len(rest) {
			r, size := utf8.DecodeRuneInString(rest)
			if r == utf8.RuneError && size <= 1 {
				rest = ""
				return -1
			}
			rest = rest[size:]
			if !gitHfsIgnorable(r) {
				return r
			}
		}
		return -1
	}
	if next() != '.' {
		return false
	}
	for index := 0; index < len(needle); index += 1 {
		r := next()
		if r < 0 || 127 < r || unicode.ToLower(r) != rune(needle[index]) {
			return false
		}
	}
	return next() < 0
}

// The code points HFS+ ignores in a name (git's next_hfs_char).
func gitHfsIgnorable(r rune) bool {
	switch {
	case 0x200c <= r && r <= 0x200f, 0x202a <= r && r <= 0x202e, 0x206a <= r && r <= 0x206f, r == 0xfeff:
		return true
	}
	return false
}

// A name folded as the widest of the file systems would compare it: decomposed with compatibility (NFKD), its
// combining marks and HFS+'s ignorable code points dropped, then case-folded.
func gitFoldName(name string) string {
	decomposed := norm.NFKD.String(name)
	stripped := strings.Map(func(r rune) rune {
		if gitHfsIgnorable(r) || unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, decomposed)
	return cases.Fold().String(stripped)
}
