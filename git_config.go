//go:build !ios_extension && !sidecar_http

// The worktree's .git/config (DESIGN-COMPUTE §13.7, IC-7, D-HARN-13; GIT-M13-01): nothing a git could run.
//
//	write   gitWriteConfig renders the whole file from the porcelain's own state (.git/ur/state) and replaces it: the
//	        repository format (core.repositoryformatversion 0), the one remote (remote.origin.url and its fetch
//	        refspec) and the branches' upstreams (branch.<b>.remote and merge), and user.name and user.email where the
//	        file held them. Never a core.* command (fsmonitor, hooksPath, sshCommand, pager, editor), an alias, an
//	        include, a filter, a hook or any other key: whatever else the file held is dropped by the next write, so a
//	        person's own git that opens the worktree finds nothing planted to run
//	read    user.name and user.email alone, which a commit's author takes (§13.4); and, to refuse and never to obey,
//	        the repository format: a version but 0 or any extensions.* key, a sha256 repository's objectformat
//	        among them, is refused before anything is written (GIT-M13-02). No other key is read, so no global
//	        excludes file, alias or include is ever honored (§13.4's ignore row)
//	values  each written value is held to what git reads back as itself: no newline, CR or NUL, quoted with git's
//	        escapes where it holds a space at its ends, a quote, a backslash or a comment character; a branch's name
//	        is a ref name already held to check-ref-format, so no section header can be closed early
//
// Package-level functions, safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The config's name.
const gitConfigName = ".git/config"

var (
	// A config that does not parse as git's: refused, never repaired from.
	ErrGitConfigInvalid = errors.New("git: a .git/config ur git cannot read")
	// A repository whose format this git does not read: a format version but 0, or an extension such as sha256's.
	ErrGitRepositoryFormat = errors.New("git: a repository format ur git does not read")
)

// What .git/config holds: see the file header.
type GitConfig struct {
	// remote.origin.url, ur://<net>/<repo>; "" for none.
	RemoteUrl string
	// Each branch's upstream, branch.<name>.remote origin and merge, by name.
	Branches []GitConfigBranch
	// user.name and user.email as the file held them; "" for none.
	UserName  string
	UserEmail string
}

// One branch's upstream.
type GitConfigBranch struct {
	// The branch's short name, its ref refs/heads/<name>.
	Name string
	// The upstream's ref on origin, refs/heads/<branch>.
	Merge string
}

// What a config's read gives: user.* and the repository format.
type gitConfigRead struct {
	userName  string
	userEmail string
	// core.repositoryformatversion as written, "" for none
	formatVersion string
	// every extensions.* key
	extensions []string
	// every key, section.subsection.key lowercased but the subsection, for TestConfigHoldsNoCommand
	keys []string
}

// The keys a config this git writes may hold, by pattern: * stands for a branch's name.
var gitConfigKeys = []string{
	"core.repositoryformatversion", "remote.origin.url", "remote.origin.fetch", "branch.*.remote", "branch.*.merge",
	"user.name", "user.email",
}

// Whether key is one gitWriteConfig writes.
func gitConfigKeyAllowed(key string) bool {
	if slices.Contains(gitConfigKeys, key) {
		return true
	}
	if rest, found := strings.CutPrefix(key, "branch."); found {
		return strings.HasSuffix(rest, ".remote") || strings.HasSuffix(rest, ".merge")
	}
	return false
}

// A value as git reads it back: bare where it can be, else quoted with git's escapes; a newline, CR or NUL refused.
func gitConfigValue(value string) (string, error) {
	if strings.ContainsAny(value, "\n\r\x00") {
		return "", fmt.Errorf("%w: a value holding a line break or NUL", ErrGitConfigInvalid)
	}
	bare := value != "" && !strings.ContainsAny(value, "\"\\#;\t") && strings.TrimSpace(value) == value
	if bare {
		return value, nil
	}
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\t", `\t`).Replace(value)
	return `"` + escaped + `"`, nil
}

// The config's bytes, rendered from config: see the file header's write row.
func gitRenderConfig(config *GitConfig) ([]byte, error) {
	builder := &strings.Builder{}
	builder.WriteString("[core]\n\trepositoryformatversion = 0\n")
	if config.RemoteUrl != "" {
		url, err := gitConfigValue(config.RemoteUrl)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(builder, "[remote \"%s\"]\n\turl = %s\n\tfetch = +%s*:%s*\n", GitRemoteName, url, GitBranchPrefix, GitRemotePrefix)
	}
	branches := slices.Clone(config.Branches)
	slices.SortFunc(branches, func(a GitConfigBranch, b GitConfigBranch) int { return strings.Compare(a.Name, b.Name) })
	for _, branch := range branches {
		if err := GitCheckRefName(GitBranchPrefix + branch.Name); err != nil {
			return nil, err
		}
		if err := GitCheckRefName(branch.Merge); err != nil {
			return nil, err
		}
		merge, err := gitConfigValue(branch.Merge)
		if err != nil {
			return nil, err
		}
		// a ref name holds no quote's newline; its quotes and backslashes are escaped as a subsection's are
		subsection := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(branch.Name)
		fmt.Fprintf(builder, "[branch \"%s\"]\n\tremote = %s\n\tmerge = %s\n", subsection, GitRemoteName, merge)
	}
	if config.UserName != "" || config.UserEmail != "" {
		builder.WriteString("[user]\n")
		for _, field := range [][2]string{{"name", config.UserName}, {"email", config.UserEmail}} {
			if field[1] == "" {
				continue
			}
			value, err := gitConfigValue(field[1])
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(builder, "\t%s = %s\n", field[0], value)
		}
	}
	return []byte(builder.String()), nil
}

// Writes .git/config whole from config, atomically, unless it holds those bytes already: see the file header.
func gitWriteConfig(fileSystem GitFileSystem, config *GitConfig) error {
	rendered, err := gitRenderConfig(config)
	if err != nil {
		return err
	}
	if current, err := gitReadFile(fileSystem, gitConfigName, int64(len(rendered))); err == nil && string(current) == string(rendered) {
		return nil
	}
	return gitWriteFileAtomic(fileSystem, gitUrDirectory, gitConfigName, rendered, 0o644, false)
}

// Reads .git/config for user.* and the repository format alone (see the file header's read row); a file that does not
// parse is ErrGitConfigInvalid, a format this git does not read ErrGitRepositoryFormat.
func gitReadConfig(fileSystem GitFileSystem, settings *GitSettings) (*gitConfigRead, error) {
	content, err := gitReadFile(fileSystem, gitConfigName, settings.ConfigByteCount)
	if err != nil {
		return nil, err
	}
	read, err := gitParseConfig(content)
	if err != nil {
		return nil, err
	}
	if (read.formatVersion != "" && read.formatVersion != "0") || 0 < len(read.extensions) {
		return nil, fmt.Errorf("%w: format version %q with extensions %v", ErrGitRepositoryFormat, read.formatVersion, read.extensions)
	}
	return read, nil
}

// git's config grammar (config.c), far enough to read every key's name and the values this file reads: sections
// `[name]`, `[name "subsection"]` and the old `[name.subsection]`; `key`, a boolean, or `key = value`; quotes, git's
// escapes and a backslash-newline continuation in a value; `#` and `;` comments outside quotes. Anything else is
// ErrGitConfigInvalid, as git refuses it.
func gitParseConfig(content []byte) (*gitConfigRead, error) {
	refused := func(what string) error {
		return fmt.Errorf("%w: %s", ErrGitConfigInvalid, what)
	}
	read := &gitConfigRead{}
	text := strings.TrimPrefix(string(content), "\ufeff")
	section := ""
	at := 0
	isKeyChar := func(c byte) bool {
		return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-'
	}
	skipSpace := func() {
		for at < len(text) && (text[at] == ' ' || text[at] == '\t' || text[at] == '\r') {
			at += 1
		}
	}
	for at < len(text) {
		skipSpace()
		if at == len(text) {
			break
		}
		switch c := text[at]; {
		case c == '\n':
			at += 1
		case c == '#' || c == ';':
			for at < len(text) && text[at] != '\n' {
				at += 1
			}
		case c == '[':
			at += 1
			start := at
			for at < len(text) && (isKeyChar(text[at]) || text[at] == '.') {
				at += 1
			}
			name := strings.ToLower(text[start:at])
			if name == "" {
				return nil, refused("a section with no name")
			}
			if at < len(text) && text[at] == ' ' {
				skipSpace()
				if at == len(text) || text[at] != '"' {
					return nil, refused("a subsection that is not quoted")
				}
				at += 1
				subsection := &strings.Builder{}
				for {
					if at == len(text) || text[at] == '\n' {
						return nil, refused("a subsection that does not end")
					}
					if text[at] == '"' {
						at += 1
						break
					}
					if text[at] == '\\' {
						at += 1
						if at == len(text) || text[at] == '\n' {
							return nil, refused("a subsection that does not end")
						}
					}
					subsection.WriteByte(text[at])
					at += 1
				}
				name += "." + subsection.String()
			} else if dot := strings.IndexByte(name, '.'); dot >= 0 {
				// the old form's subsection is lowercased, as git reads it
				name = name[:dot] + "." + strings.ToLower(name[dot+1:])
			}
			if at == len(text) || text[at] != ']' {
				return nil, refused("a section header that does not close")
			}
			at += 1
			section = name
		case isKeyChar(c):
			if section == "" {
				return nil, refused("a key before any section")
			}
			start := at
			for at < len(text) && isKeyChar(text[at]) {
				at += 1
			}
			key := strings.ToLower(text[start:at])
			skipSpace()
			value := ""
			hasValue := false
			if at < len(text) && text[at] == '=' {
				at += 1
				hasValue = true
				parsed, next, err := gitParseConfigValue(text, at)
				if err != nil {
					return nil, err
				}
				value, at = parsed, next
			} else if at < len(text) && text[at] != '\n' && text[at] != '#' && text[at] != ';' {
				return nil, refused("a key followed by neither = nor the line's end")
			}
			full := section + "." + key
			read.keys = append(read.keys, full)
			switch {
			case full == "user.name" && hasValue:
				read.userName = value
			case full == "user.email" && hasValue:
				read.userEmail = value
			case full == "core.repositoryformatversion":
				read.formatVersion = value
			case strings.HasPrefix(full, "extensions."):
				read.extensions = append(read.extensions, full)
			}
		default:
			return nil, refused("a line that is no section, key or comment")
		}
	}
	return read, nil
}

// A value from text at at, to its line's end or a comment outside quotes, with git's escapes and continuations, its
// unquoted trailing space dropped: the value and where its line ends.
func gitParseConfigValue(text string, at int) (string, int, error) {
	value := &strings.Builder{}
	quoted := false
	// the length of value before its unquoted trailing space, which is dropped at the end
	kept := 0
	started := false
	for at < len(text) {
		c := text[at]
		switch {
		case c == '\n' && !quoted:
			return value.String()[:kept], at, nil
		case c == '\n':
			return "", at, fmt.Errorf("%w: a quoted value that does not end on its line", ErrGitConfigInvalid)
		case !quoted && (c == '#' || c == ';'):
			for at < len(text) && text[at] != '\n' {
				at += 1
			}
			return value.String()[:kept], at, nil
		case c == '"':
			quoted = !quoted
			at += 1
			kept = value.Len()
			started = true
			continue
		case c == '\\':
			at += 1
			if at == len(text) {
				return "", at, fmt.Errorf("%w: an escape at the file's end", ErrGitConfigInvalid)
			}
			switch text[at] {
			case '\n':
				// a continuation
			case 'n':
				value.WriteByte('\n')
			case 't':
				value.WriteByte('\t')
			case 'b':
				value.WriteByte('\b')
			case '\\', '"':
				value.WriteByte(text[at])
			default:
				return "", at, fmt.Errorf("%w: an escape git does not read", ErrGitConfigInvalid)
			}
			at += 1
			kept = value.Len()
			started = true
			continue
		case (c == ' ' || c == '\t' || c == '\r') && !quoted:
			if started {
				value.WriteByte(c)
			}
			at += 1
			continue
		}
		value.WriteByte(c)
		at += 1
		kept = value.Len()
		started = true
	}
	if quoted {
		return "", at, fmt.Errorf("%w: a quoted value that does not end", ErrGitConfigInvalid)
	}
	return value.String()[:kept], at, nil
}
