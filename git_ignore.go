//go:build !ios_extension && !sidecar_http

// The ignore rules (DESIGN-COMPUTE §13.4's ignore row; GIT-M13-01): .gitignore files and .git/info/exclude by
// gitignore(5), as git's dir.c reads them, for status and add -A. No global excludes file is read, since config is
// not read beyond user.* (§13.7).
//
//	files     each directory's .gitignore, read when a path below it is asked about, and .git/info/exclude; a file
//	          past GitSettings.IgnoreFileByteCount, or one that is a link, is passed over, as git passes them over
//	lines     a UTF-8 BOM skipped; blank lines and lines opening with # skipped; trailing spaces dropped unless escaped
//	          with a backslash; a CR before the newline dropped; ! negates, \! and \# escape
//	patterns  git's parse_path_pattern: a trailing / matches directories alone; a pattern with no other / matches a
//	          name at any depth (match_basename), else the path relative to its file's directory (match_pathname,
//	          a leading / anchoring it); globs by git's wildmatch: * and ? never cross a /, ** across directories
//	          where it stands alone between slashes, [...] classes with ranges, ! or ^ and [:class:]
//	order     the last matching line of a file decides; a deeper directory's file over a shallower one's, every
//	          .gitignore over info/exclude (git's EXC_DIRS before EXC_FILE)
//	parents   a path below an excluded directory is excluded by that directory's pattern, whatever its own files say,
//	          since git never reads into a directory it excludes ("It is not possible to re-include a file if a
//	          parent directory of that file is excluded")
//	case      matched without case where the worktree's file system folds case (GitWorktree's probe), as git's
//	          core.ignorecase makes it
//
// Not safe for concurrent use: it caches each directory's patterns as it reads them.

package sidecar

import (
	"bytes"
	"errors"
	"io/fs"
	"path"
	"strings"
)

// The files the rules are read from.
const (
	gitIgnoreFileName = ".gitignore"
	gitExcludeName    = ".git/info/exclude"
)

// The pattern flags git's parse_path_pattern sets.
const (
	gitPatternNegative = 1 << iota
	gitPatternMustBeDir
	gitPatternNoDir
	gitPatternEndsWith
)

// One line's pattern.
type gitPattern struct {
	pattern string
	// git's nowildcardlen: the bytes before the first glob character
	noWildcardLength int
	flags            int
	// the directory its file sits in, with a trailing /, "" for the top and info/exclude
	base string
	// where it came from, for check-ignore's -v: the file's name and its line
	source string
	line   int
}

// The match a path's rules give it: the deciding pattern, nil for none.
type GitIgnoreMatch struct {
	// The file the pattern came from, .gitignore's path or .git/info/exclude.
	Source string
	// Its 1-based line.
	Line int
	// The line's pattern as written, with its ! and trailing / ("!foo", "build/").
	Pattern string
	// Whether the pattern re-includes: a match that does not exclude.
	Negative bool
}

// One worktree's ignore rules.
type GitIgnore struct {
	fileSystem GitFileSystem
	settings   *GitSettings
	ignoreCase bool
	// each directory's patterns, read once, by its path with a trailing / ("" for the top)
	directoryPatterns map[string][]*gitPattern
	// info/exclude's
	excludePatterns []*gitPattern
}

// The rules of the worktree on fileSystem, matched without case when ignoreCase is set.
func NewGitIgnore(fileSystem GitFileSystem, settings *GitSettings, ignoreCase bool) (*GitIgnore, error) {
	ignore := &GitIgnore{fileSystem: fileSystem, settings: settings, ignoreCase: ignoreCase, directoryPatterns: map[string][]*gitPattern{}}
	patterns, err := ignore.readPatterns(gitExcludeName, "")
	if err != nil {
		return nil, err
	}
	ignore.excludePatterns = patterns
	return ignore, nil
}

// Whether path, a file or with isDirectory a directory, is excluded.
func (self *GitIgnore) Ignored(path string, isDirectory bool) (bool, error) {
	match, err := self.Match(path, isDirectory)
	if err != nil || match == nil {
		return false, err
	}
	return !match.Negative, nil
}

// The pattern that decides path, nil for none, by the file header's order and parents rows.
func (self *GitIgnore) Match(filePath string, isDirectory bool) (*GitIgnoreMatch, error) {
	// each leading directory, shallowest first: one excluded decides everything below it
	for slash := strings.IndexByte(filePath, '/'); slash >= 0; {
		directory := filePath[:slash]
		pattern, err := self.lastMatching(directory, true)
		if err != nil {
			return nil, err
		}
		if pattern != nil && pattern.flags&gitPatternNegative == 0 {
			return pattern.match(), nil
		}
		next := strings.IndexByte(filePath[slash+1:], '/')
		if next < 0 {
			break
		}
		slash += 1 + next
	}
	pattern, err := self.lastMatching(filePath, isDirectory)
	if err != nil || pattern == nil {
		return nil, err
	}
	return pattern.match(), nil
}

// The match a pattern gives.
func (self *gitPattern) match() *GitIgnoreMatch {
	written := self.pattern
	if self.flags&gitPatternMustBeDir != 0 {
		written += "/"
	}
	if self.flags&gitPatternNegative != 0 {
		written = "!" + written
	}
	return &GitIgnoreMatch{Source: self.source, Line: self.line, Pattern: written, Negative: self.flags&gitPatternNegative != 0}
}

// The last pattern matching path among the .gitignore files from its directory up, deepest first, then info/exclude
// (git's last_matching_pattern_from_lists).
func (self *GitIgnore) lastMatching(filePath string, isDirectory bool) (*gitPattern, error) {
	basename := path.Base(filePath)
	directories := []string{""}
	for slash := strings.IndexByte(filePath, '/'); slash >= 0; {
		directories = append(directories, filePath[:slash+1])
		next := strings.IndexByte(filePath[slash+1:], '/')
		if next < 0 {
			break
		}
		slash += 1 + next
	}
	for index := len(directories) - 1; index >= 0; index -= 1 {
		patterns, err := self.directory(directories[index])
		if err != nil {
			return nil, err
		}
		if pattern := self.lastMatchingFromList(filePath, basename, isDirectory, patterns); pattern != nil {
			return pattern, nil
		}
	}
	return self.lastMatchingFromList(filePath, basename, isDirectory, self.excludePatterns), nil
}

// git's last_matching_pattern_from_list over one file's patterns, last line first.
func (self *GitIgnore) lastMatchingFromList(filePath string, basename string, isDirectory bool, patterns []*gitPattern) *gitPattern {
	for index := len(patterns) - 1; index >= 0; index -= 1 {
		pattern := patterns[index]
		if pattern.flags&gitPatternMustBeDir != 0 && !isDirectory {
			continue
		}
		if pattern.flags&gitPatternNoDir != 0 {
			if self.matchBasename(basename, pattern) {
				return pattern
			}
			continue
		}
		if self.matchPathname(filePath, pattern) {
			return pattern
		}
	}
	return nil
}

// A directory's patterns, its .gitignore read on first ask.
func (self *GitIgnore) directory(base string) ([]*gitPattern, error) {
	if patterns, ok := self.directoryPatterns[base]; ok {
		return patterns, nil
	}
	patterns, err := self.readPatterns(base+gitIgnoreFileName, base)
	if err != nil {
		return nil, err
	}
	self.directoryPatterns[base] = patterns
	return patterns, nil
}

// One file's patterns: none for a file that does not stand, is a link or passes the byte count.
func (self *GitIgnore) readPatterns(name string, base string) ([]*gitPattern, error) {
	info, err := self.fileSystem.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || self.settings.IgnoreFileByteCount < info.Size() {
		return nil, nil
	}
	content, err := gitReadFile(self.fileSystem, name, self.settings.IgnoreFileByteCount)
	if errors.Is(err, ErrGitFileTooLarge) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return gitParsePatterns(content, base, name), nil
}

// A file's lines as patterns, by the file header's lines row (git's add_patterns_from_buffer).
func gitParsePatterns(content []byte, base string, source string) []*gitPattern {
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf"))
	patterns := []*gitPattern{}
	lines := strings.Split(string(content), "\n")
	for index, line := range lines {
		if index == len(lines)-1 && line == "" {
			break
		}
		if line == "" || line[0] == '#' {
			continue
		}
		line = strings.TrimSuffix(line, "\r")
		line = gitTrimTrailingSpaces(line)
		pattern := &gitPattern{base: base, source: source, line: index + 1}
		if strings.HasPrefix(line, "!") {
			pattern.flags |= gitPatternNegative
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			pattern.flags |= gitPatternMustBeDir
			line = line[:len(line)-1]
		}
		if !strings.Contains(line, "/") {
			pattern.flags |= gitPatternNoDir
		}
		pattern.noWildcardLength = gitSimpleLength(line)
		if strings.HasPrefix(line, "*") && gitSimpleLength(line[1:]) == len(line)-1 {
			pattern.flags |= gitPatternEndsWith
		}
		pattern.pattern = line
		patterns = append(patterns, pattern)
	}
	return patterns
}

// git's trim_trailing_spaces: spaces at the end dropped, one escaped with a backslash kept.
func gitTrimTrailingSpaces(line string) string {
	lastSpace := -1
	for index := 0; index < len(line); index += 1 {
		switch line[index] {
		case ' ':
			if lastSpace < 0 {
				lastSpace = index
			}
		case '\\':
			index += 1
			if index == len(line) {
				return line
			}
			lastSpace = -1
		default:
			lastSpace = -1
		}
	}
	if lastSpace >= 0 {
		return line[:lastSpace]
	}
	return line
}

// The bytes before the first glob character (git's simple_length).
func gitSimpleLength(pattern string) int {
	for index := 0; index < len(pattern); index += 1 {
		if strings.IndexByte("*?[\\", pattern[index]) != -1 {
			return index
		}
	}
	return len(pattern)
}

// Compares bytes as the rules' case says (git's fspathncmp).
func (self *GitIgnore) equalBytes(a string, b string) bool {
	if self.ignoreCase {
		return gitAsciiFoldEqual(a, b)
	}
	return a == b
}

// Whether a and b are equal with ASCII case folded, as git's strncasecmp folds it.
func gitAsciiFoldEqual(a string, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := 0; index < len(a); index += 1 {
		if gitAsciiLower(a[index]) != gitAsciiLower(b[index]) {
			return false
		}
	}
	return true
}

// A byte lowercased if it is an ASCII capital.
func gitAsciiLower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// git's match_basename.
func (self *GitIgnore) matchBasename(basename string, pattern *gitPattern) bool {
	text := pattern.pattern
	switch {
	case pattern.noWildcardLength == len(text):
		return self.equalBytes(text, basename)
	case pattern.flags&gitPatternEndsWith != 0:
		literal := text[1:]
		return len(literal) <= len(basename) && self.equalBytes(literal, basename[len(basename)-len(literal):])
	}
	return gitWildmatch(text, basename, false, self.ignoreCase)
}

// git's match_pathname: the pattern relative to its file's directory, a leading / dropped, its literal prefix
// compared first.
func (self *GitIgnore) matchPathname(filePath string, pattern *gitPattern) bool {
	text := pattern.pattern
	prefix := pattern.noWildcardLength
	if strings.HasPrefix(text, "/") {
		text = text[1:]
		prefix -= 1
	}
	base := strings.TrimSuffix(pattern.base, "/")
	if len(filePath) < len(base)+1 || (base != "" && (filePath[len(base)] != '/' || !self.equalBytes(filePath[:len(base)], base))) {
		return false
	}
	name := filePath
	if base != "" {
		name = filePath[len(base)+1:]
	}
	if 0 < prefix {
		if len(name) < prefix || !self.equalBytes(text[:prefix], name[:prefix]) {
			return false
		}
		text, name = text[prefix:], name[prefix:]
		if text == "" && name == "" {
			return true
		}
	}
	return gitWildmatch(text, name, true, self.ignoreCase)
}

// git's wildmatch's answers.
const (
	gitWildMatch = iota
	gitWildNoMatch
	gitWildAbortAll
	gitWildAbortToStarStar
)

// Whether text matches pattern by git's wildmatch.c, with pathname making * and ? stop at a slash (WM_PATHNAME) and
// ignoreCase folding ASCII case (WM_CASEFOLD).
func gitWildmatch(pattern string, text string, pathname bool, ignoreCase bool) bool {
	return gitDowild(pattern, 0, text, 0, pathname, ignoreCase) == gitWildMatch
}

// Whether c is a character wildmatch treats as special.
func gitGlobSpecial(c byte) bool {
	return c == '*' || c == '?' || c == '[' || c == '\\'
}

// wildmatch.c's dowild, over pattern from p and text from t.
func gitDowild(pattern string, p int, text string, t int, pathname bool, ignoreCase bool) int {
	lower := func(c byte) byte {
		if ignoreCase {
			return gitAsciiLower(c)
		}
		return c
	}
	at := func(s string, index int) byte {
		if index < len(s) {
			return s[index]
		}
		return 0
	}
	for ; p < len(pattern); p, t = p+1, t+1 {
		pc := pattern[p]
		tc := at(text, t)
		if t >= len(text) && pc != '*' {
			return gitWildAbortAll
		}
		tc, pc = lower(tc), lower(pc)
		switch pc {
		case '\\':
			// the escaped character compared as written, never folded, as wildmatch.c compares it
			p += 1
			pc = at(pattern, p)
			if tc != pc {
				return gitWildNoMatch
			}
			continue
		case '?':
			if pathname && tc == '/' {
				return gitWildNoMatch
			}
			continue
		case '*':
			matchSlash := false
			p += 1
			if at(pattern, p) == '*' {
				previous := p - 2
				for at(pattern, p+1) == '*' {
					p += 1
				}
				p += 1
				if (previous < 0 || pattern[previous] == '/') &&
					(p == len(pattern) || pattern[p] == '/' || (pattern[p] == '\\' && at(pattern, p+1) == '/')) {
					if p < len(pattern) && pattern[p] == '/' && gitDowild(pattern, p+1, text, t, pathname, ignoreCase) == gitWildMatch {
						return gitWildMatch
					}
					matchSlash = true
				} else {
					// a ** not standing alone between slashes is one *, which crosses no slash
					matchSlash = false
				}
			} else {
				matchSlash = !pathname
			}
			if p == len(pattern) {
				if !matchSlash && strings.IndexByte(text[t:], '/') >= 0 {
					return gitWildNoMatch
				}
				return gitWildMatch
			}
			if !matchSlash && pattern[p] == '/' {
				slash := strings.IndexByte(text[t:], '/')
				if slash < 0 {
					return gitWildNoMatch
				}
				// the slash is matched by the loop's next round
				t += slash
				break
			}
			for {
				if t >= len(text) {
					break
				}
				if !gitGlobSpecial(pattern[p]) {
					literal := lower(pattern[p])
					for t < len(text) && (matchSlash || text[t] != '/') && lower(text[t]) != literal {
						t += 1
					}
					if t >= len(text) || lower(text[t]) != literal {
						if matchSlash {
							return gitWildAbortAll
						}
						return gitWildAbortToStarStar
					}
				}
				matched := gitDowild(pattern, p, text, t, pathname, ignoreCase)
				if matched != gitWildNoMatch {
					if !matchSlash || matched != gitWildAbortToStarStar {
						return matched
					}
				} else if !matchSlash && text[t] == '/' {
					return gitWildAbortToStarStar
				}
				t += 1
			}
			return gitWildAbortAll
		case '[':
			p += 1
			pc = at(pattern, p)
			if pc == '^' {
				pc = '!'
			}
			negated := pc == '!'
			if negated {
				p += 1
				pc = at(pattern, p)
			}
			previous := byte(0)
			matched := false
			for {
				if p >= len(pattern) {
					return gitWildAbortAll
				}
				switch {
				case pc == '\\':
					p += 1
					if p >= len(pattern) {
						return gitWildAbortAll
					}
					pc = pattern[p]
					if tc == pc {
						matched = true
					}
				case pc == '-' && previous != 0 && p+1 < len(pattern) && pattern[p+1] != ']':
					p += 1
					pc = pattern[p]
					if pc == '\\' {
						p += 1
						if p >= len(pattern) {
							return gitWildAbortAll
						}
						pc = pattern[p]
					}
					if previous <= tc && tc <= pc {
						matched = true
					} else if ignoreCase && 'a' <= tc && tc <= 'z' {
						upper := tc - 'a' + 'A'
						if previous <= upper && upper <= pc {
							matched = true
						}
					}
					pc = 0
				case pc == '[' && at(pattern, p+1) == ':':
					start := p + 2
					end := start
					for end < len(pattern) && pattern[end] != ']' {
						end += 1
					}
					if end >= len(pattern) {
						return gitWildAbortAll
					}
					if end-start < 1 || pattern[end-1] != ':' {
						// no ":]": a plain [ in the set
						pc = '['
						if tc == pc {
							matched = true
						}
						break
					}
					class := pattern[start : end-1]
					p = end
					inClass, known := gitWildClass(class, tc, ignoreCase)
					if !known {
						return gitWildAbortAll
					}
					if inClass {
						matched = true
					}
					pc = 0
				default:
					if tc == pc {
						matched = true
					}
				}
				previous = pc
				p += 1
				if p >= len(pattern) {
					return gitWildAbortAll
				}
				pc = pattern[p]
				if pc == ']' {
					break
				}
			}
			if matched == negated || (pathname && tc == '/') {
				return gitWildNoMatch
			}
			continue
		default:
			if tc != pc {
				return gitWildNoMatch
			}
			continue
		}
	}
	if t < len(text) {
		return gitWildNoMatch
	}
	return gitWildMatch
}

// Whether c is in the named class, git's sane_ctype's ASCII classes, and whether the name is one.
func gitWildClass(class string, c byte, ignoreCase bool) (bool, bool) {
	isUpper := 'A' <= c && c <= 'Z'
	isLower := 'a' <= c && c <= 'z'
	isDigit := '0' <= c && c <= '9'
	isAlpha := isUpper || isLower
	isPrint := 0x20 <= c && c <= 0x7e
	switch class {
	case "alnum":
		return isAlpha || isDigit, true
	case "alpha":
		return isAlpha, true
	case "blank":
		return c == ' ' || c == '\t', true
	case "cntrl":
		return c < 0x20 || c == 0x7f, true
	case "digit":
		return isDigit, true
	case "graph":
		return isPrint && c != ' ', true
	case "lower":
		return isLower, true
	case "print":
		return isPrint, true
	case "punct":
		return isPrint && c != ' ' && !isAlpha && !isDigit, true
	case "space":
		return c == ' ' || c == '\t' || c == '\n' || c == '\r', true
	case "upper":
		return isUpper || (ignoreCase && isLower), true
	case "xdigit":
		return isDigit || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F'), true
	}
	return false, false
}
