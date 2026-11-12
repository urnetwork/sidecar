//go:build !js && !ios && !android && !sdk_mobile_bind

// The project file and a call's network (§5.8, CORE-M3-05; owner decisions 23, 170; D-DNS-2). `.ur` is TOML at a
// project root, holding no secret and safe to commit: `network`, a label or alias, `agent`, the default --agent, and
// `claims` and `project`, §16.11's announcement setting and label, which daemon_claims.go applies (CORE-M6-02). The
// daemon finds it from the hello's cwd up, each directory's own `.ur` first, stopping after the git top level or $HOME.
//
// A committed `.ur` is hostile input, so it is read by a strict parser of this one flat form rather than a TOML module:
// at most SidecarProjectSettings.MaxByteCount (4 KiB) of UTF-8 lines, each blank, a comment, or `key = "value"` with an
// optional trailing comment, the keys above once each, values in basic strings with no escape. Anything else is refused
// whole, and a refusal names its line number and nothing of the file.
//
// A project (§16.11's runs paragraph) is keyed by its git top level's remote, else a hash of its path
// (SidecarProjectKey), which the harness config's per-project claims and a confirmation name; and one that is no evs repo
// announces `.ur`'s `project`, else its remote's host and path without user info, port, query or fragment, else its top
// level's base name (SidecarProject.ProjectLabel). The remote is read from the work tree's own git config, by a bounded
// parser of its [remote] sections, and never by running git: a hostile repository's config names programs git would
// run.
//
// A network-scoped call acts on its network argument, else `.ur`'s, else the only network the daemon hosts; otherwise
// it fails with §5.8's FAILED_PRECONDITION naming the networks. A name resolves by §12's ResolveNetworkLabel: a label,
// an alias or a retiring alias, and a legacy network_name only as a person's typed input, a control-mode argument,
// never from `.ur` or a git remote, whose name another network may later hold. A network id names its network too.

package sidecar

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// The project file's name.
const sidecarProjectFileName = ".ur"

// A project key's form when its work tree has no remote: this prefix, then 32 lowercase hex of its top level's path's
// SHA-256.
const sidecarProjectPathKeyPrefix = "path:"

// `.ur`'s format limits and the bounds on what a project's git config is read for (§5.8). The format's limits are
// shared by every reader of `.ur`, so they change only with the format.
type SidecarProjectSettings struct {
	// The longest `.ur` read: 4 KiB, far past four short keys and their comments.
	MaxByteCount int
	// The longest value in it: 64 B, an agent label's most.
	MaxValueByteCount int
	// The most of a work tree's git config read for its remote: 64 KiB, far past any hand-written one. A longer one
	// gives no remote, so the project keys by its path.
	GitConfigByteCount int64
	// The most a confirmation of a project's claims value takes in the network's sealed state (daemon_claims.go): 4 KiB,
	// a project key and two values.
	ConfirmationByteCount int64
}

// A fresh value each call.
func DefaultSidecarProjectSettings() *SidecarProjectSettings {
	return &SidecarProjectSettings{
		MaxByteCount:          4 * 1024,
		MaxValueByteCount:     64,
		GitConfigByteCount:    64 * 1024,
		ConfirmationByteCount: 4 * 1024,
	}
}

// A `.ur` that is not the flat form. The error names a line, never the file's text.
var ErrSidecarProjectMalformed = errors.New(".ur is not the flat form ur reads")

// A project's `.ur` (§5.8).
type SidecarProject struct {
	// A label or alias of a network, lowercase (D-DNS-2). Empty: none named.
	Network string
	// The default --agent. Empty: none.
	Agent string
	// §16.11's announcement setting, off, prompt or auto. Empty: the member's. CORE-M6-02 applies it.
	Claims string
	// The label the project's runs announce (§16.11). CORE-M6-02 applies it.
	Project string
	// The directory it was found in.
	Directory string
}

// The flat form's refusal at line, which repeats nothing of it.
func sidecarProjectMalformed(line int) error {
	if line == 0 {
		return ErrSidecarProjectMalformed
	}
	return fmt.Errorf("%w: line %d", ErrSidecarProjectMalformed, line)
}

// Whether text holds a control character other than a tab.
func hasSidecarProjectControl(text string) bool {
	for _, r := range text {
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f || (0x80 <= r && r < 0xa0) {
			return true
		}
	}
	return false
}

// Parses one `.ur`'s bytes under the format's default limits, refusing anything but the flat form.
func ParseSidecarProject(content []byte) (*SidecarProject, error) {
	return ParseSidecarProjectWithSettings(content, DefaultSidecarProjectSettings())
}

// Parses one `.ur`'s bytes under settings' limits, refusing anything but the flat form.
func ParseSidecarProjectWithSettings(content []byte, settings *SidecarProjectSettings) (*SidecarProject, error) {
	if settings.MaxByteCount < len(content) || !utf8.Valid(content) || strings.HasPrefix(string(content), "\xef\xbb\xbf") {
		return nil, sidecarProjectMalformed(0)
	}
	project := &SidecarProject{}
	seen := map[string]bool{}
	for index, line := range strings.Split(string(content), "\n") {
		number := index + 1
		line = strings.TrimSuffix(line, "\r")
		if hasSidecarProjectControl(line) {
			return nil, sidecarProjectMalformed(number)
		}
		trimmed := strings.Trim(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, rest, found := strings.Cut(trimmed, "=")
		key = strings.TrimRight(key, " \t")
		rest = strings.TrimLeft(rest, " \t")
		if !found || seen[key] || !strings.HasPrefix(rest, `"`) {
			return nil, sidecarProjectMalformed(number)
		}
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 {
			return nil, sidecarProjectMalformed(number)
		}
		value := rest[1 : 1+end]
		after := strings.TrimLeft(rest[2+end:], " \t")
		if (after != "" && !strings.HasPrefix(after, "#")) || strings.ContainsRune(value, '\\') ||
			value == "" || settings.MaxValueByteCount < len(value) {
			return nil, sidecarProjectMalformed(number)
		}
		seen[key] = true
		switch key {
		case "network":
			network := dnsAsciiLower(value)
			if !isDnsLowerLdhLabel(network) {
				return nil, sidecarProjectMalformed(number)
			}
			project.Network = network
		case "agent":
			if _, err := ParseSidecarAgent(value); err != nil {
				return nil, sidecarProjectMalformed(number)
			}
			project.Agent = value
		case "claims":
			if value != "off" && value != "prompt" && value != "auto" {
				return nil, sidecarProjectMalformed(number)
			}
			project.Claims = value
		case "project":
			if _, err := ParseSidecarAgent(value); err != nil {
				return nil, sidecarProjectMalformed(number)
			}
			project.Project = value
		default:
			return nil, sidecarProjectMalformed(number)
		}
	}
	return project, nil
}

// Finds `.ur` from cwd up under the format's default limits (FindSidecarProjectWithSettings).
func FindSidecarProject(cwd string, home string) (*SidecarProject, error) {
	return FindSidecarProjectWithSettings(cwd, home, DefaultSidecarProjectSettings())
}

// Finds `.ur` from cwd up: each directory's own first, stopping after the git top level, a directory holding .git, or
// home, or at the root. Nil with no error when there is none, and for a cwd that is not absolute. A `.ur` that is not a
// regular file, cannot be read or does not parse is refused, never skipped, since the person meant it to scope.
func FindSidecarProjectWithSettings(cwd string, home string, settings *SidecarProjectSettings) (*SidecarProject, error) {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return nil, nil
	}
	directory := filepath.Clean(cwd)
	home = filepath.Clean(home)
	for {
		path := filepath.Join(directory, sidecarProjectFileName)
		info, err := os.Lstat(path)
		switch {
		case err == nil:
			if !info.Mode().IsRegular() || int64(settings.MaxByteCount) < info.Size() {
				return nil, sidecarProjectMalformed(0)
			}
			project, err := readSidecarProject(path, settings)
			if err != nil {
				return nil, err
			}
			project.Directory = directory
			return project, nil
		case !errors.Is(err, os.ErrNotExist):
			return nil, sidecarProjectMalformed(0)
		}
		if _, err := os.Lstat(filepath.Join(directory, ".git")); err == nil {
			// the git top level: a work tree's .git is a directory, a linked one's a file
			return nil, nil
		}
		if home != "" && directory == home {
			return nil, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil, nil
		}
		directory = parent
	}
}

// Reads and parses path, reading at most one byte past the bound so a file grown since its stat is refused.
func readSidecarProject(path string, settings *SidecarProjectSettings) (*SidecarProject, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, sidecarProjectMalformed(0)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, int64(settings.MaxByteCount)+1))
	if err != nil {
		return nil, sidecarProjectMalformed(0)
	}
	return ParseSidecarProjectWithSettings(content, settings)
}

// A project's work tree as its git layout shows it: its top level, the directory holding .git, and the config its
// remotes are read from, "" for none.
type SidecarProjectTree struct {
	TopLevel string
	// A work tree was found: TopLevel holds .git.
	Git bool
	// The remote's url as the config writes it: origin's, else the first [remote] section's with one; "" for none.
	Remote string
}

// The work tree cwd is in: from cwd up to the first directory holding .git, a directory or a linked work tree's file,
// stopping after home or at the root. Its remote is read from that tree's git config (readSidecarGitRemote). A cwd
// outside every work tree is its own top level, with no remote. Nil for a cwd that is not absolute.
func FindSidecarProjectTree(cwd string, home string, settings *SidecarProjectSettings) *SidecarProjectTree {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return nil
	}
	start := filepath.Clean(cwd)
	home = filepath.Clean(home)
	directory := start
	for {
		gitPath := filepath.Join(directory, ".git")
		if info, err := os.Lstat(gitPath); err == nil {
			tree := &SidecarProjectTree{TopLevel: directory, Git: true}
			if configPath := sidecarGitConfigPath(gitPath, info, settings); configPath != "" {
				tree.Remote = readSidecarGitRemote(configPath, settings)
			}
			return tree
		}
		if home != "" && directory == home {
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	return &SidecarProjectTree{TopLevel: start}
}

// The git config a work tree's .git names: .git/config for a directory; for a linked work tree's file, its gitdir's
// commondir's config, else the gitdir's own. "" when the layout does not read.
func sidecarGitConfigPath(gitPath string, info os.FileInfo, settings *SidecarProjectSettings) string {
	if info.IsDir() {
		return filepath.Join(gitPath, "config")
	}
	if !info.Mode().IsRegular() || settings.MaxByteCount < int(info.Size()) {
		return ""
	}
	content, err := os.ReadFile(gitPath)
	if err != nil {
		return ""
	}
	gitDir, found := strings.CutPrefix(strings.TrimSpace(string(content)), "gitdir:")
	gitDir = strings.TrimSpace(gitDir)
	if !found || gitDir == "" {
		return ""
	}
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(filepath.Dir(gitPath), gitDir)
	}
	if common, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil && len(common) <= settings.MaxByteCount {
		commonDir := strings.TrimSpace(string(common))
		if !filepath.IsAbs(commonDir) {
			commonDir = filepath.Join(gitDir, commonDir)
		}
		return filepath.Join(commonDir, "config")
	}
	return filepath.Join(gitDir, "config")
}

// The remote url a git config names: [remote "origin"]'s url, else the first [remote "<name>"] section's, "" for none
// or for a config past GitConfigByteCount. Only section headers and url keys are read, values unquoted when quoted;
// every other line is passed over, so nothing in the file is run or followed.
func readSidecarGitRemote(configPath string, settings *SidecarProjectSettings) string {
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, settings.GitConfigByteCount+1))
	if err != nil || settings.GitConfigByteCount < int64(len(content)) {
		return ""
	}
	section := ""
	first := ""
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 4*1024), int(settings.GitConfigByteCount)+1)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			section = ""
			header, _, closed := strings.Cut(strings.TrimPrefix(line, "["), "]")
			name, subsection, quoted := strings.Cut(strings.TrimSpace(header), " ")
			if closed && quoted && strings.EqualFold(name, "remote") {
				subsection = strings.TrimSpace(subsection)
				if len(subsection) >= 2 && strings.HasPrefix(subsection, `"`) && strings.HasSuffix(subsection, `"`) {
					section = subsection[1 : len(subsection)-1]
				}
			}
			continue
		}
		if section == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "url") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		}
		if value == "" {
			continue
		}
		if section == "origin" {
			return value
		}
		if first == "" {
			first = value
		}
	}
	return first
}

// A remote's host and path, as a project names itself (§16.11): lowercase host, no scheme, user info, port, query or
// fragment, the path without its leading or trailing slash or a trailing .git. Empty for a remote with no host, a
// local path or a file url, and for one whose host or path holds a control character or whitespace, so no local path
// and nothing unprintable becomes a label.
func sidecarRemoteHostPath(remote string) string {
	remote = strings.TrimSpace(remote)
	host := ""
	path := ""
	if strings.Contains(remote, "://") {
		parsed, err := url.Parse(remote)
		if err != nil || parsed.Scheme == "file" {
			return ""
		}
		host = parsed.Hostname()
		path = parsed.Path
	} else {
		// scp's form, [user@]host:path, whose host holds no slash
		before, after, found := strings.Cut(remote, ":")
		if !found || before == "" || strings.ContainsAny(before, `/\`) {
			return ""
		}
		if _, hostPart, hasUser := strings.Cut(before, "@"); hasUser {
			before = hostPart
		}
		host = before
		path = after
	}
	host = strings.ToLower(host)
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimSuffix(path, "/")
	if host == "" || path == "" {
		return ""
	}
	hostPath := host + "/" + path
	for _, r := range hostPath {
		if r <= 0x20 || r == 0x7f || (0x80 <= r && r < 0xa0) || r == '\\' {
			return ""
		}
	}
	if !utf8.ValidString(hostPath) {
		return ""
	}
	return hostPath
}

// §16.11's project key: the work tree's remote's host and path, else path: and 32 lowercase hex of SHA-256 of its top
// level, which the harness config's per-project claims and a confirmation name. "" for no tree.
func SidecarProjectKey(tree *SidecarProjectTree) string {
	if tree == nil {
		return ""
	}
	if hostPath := sidecarRemoteHostPath(tree.Remote); hostPath != "" {
		return hostPath
	}
	sum := sha256.Sum256([]byte(tree.TopLevel))
	return sidecarProjectPathKeyPrefix + hex.EncodeToString(sum[:16])
}

// §16.11's label a project's runs announce when it is no evs repo: `.ur`'s project, else the remote's host and path
// without user info, port, query or fragment, else the top level's base name. A label past the directory's project cap
// falls back to the base name, and "" answers a tree that names nothing. The writer still holds what it announces to
// the directory's classes and redaction (directory_fields.go). Safe on a nil project, with no `.ur`.
func (self *SidecarProject) ProjectLabel(tree *SidecarProjectTree) string {
	if self != nil && self.Project != "" {
		return self.Project
	}
	if tree == nil {
		return ""
	}
	if hostPath := sidecarRemoteHostPath(tree.Remote); hostPath != "" && len(hostPath) <= DirectoryProjectByteCount {
		return hostPath
	}
	base := filepath.Base(tree.TopLevel)
	if base == "." || base == string(filepath.Separator) || DirectoryProjectByteCount < len(base) {
		return ""
	}
	return base
}

// §5.8's FAILED_PRECONDITION for a network-scoped call: no network named or hosted, a name that resolves to none of
// this client's networks, or several and none chosen. It names the hosted networks, by label where the table holds
// one, else by id, and never the name asked for or anything of `.ur`.
type DaemonNetworkError struct {
	// none: the daemon hosts no network; unknown: the name resolves to no hosted network; ambiguous: several are
	// hosted and the call chose none; project: `.ur` does not parse.
	Reason string
	// The hosted networks, for the person to choose from.
	Networks []string
}

// The reason and the networks.
func (self *DaemonNetworkError) Error() string {
	switch self.Reason {
	case "none":
		return "no network: enroll one with ur login"
	case "project":
		return "the project's .ur does not parse: fix it, or name the network"
	case "unknown":
		return "no network of this client goes by that name: one of " + strings.Join(self.Networks, ", ")
	}
	return "several networks: name one of " + strings.Join(self.Networks, ", ")
}

// One session's view of its caller: its hello and, read once and fixed for the session, its project's `.ur`. Used by
// its session's goroutine only.
type daemonSession struct {
	hello       *DaemonHello
	projectRead bool
	project     *SidecarProject
	projectErr  error
}

// The session's `.ur`, found on first use.
func (self *Daemon) sessionProject(session *daemonSession) (*SidecarProject, error) {
	if !session.projectRead {
		session.projectRead = true
		session.project, session.projectErr = FindSidecarProjectWithSettings(session.hello.Cwd, self.home(), self.projectSettings())
	}
	return session.project, session.projectErr
}

// `.ur`'s limits as the daemon's settings hold them, the defaults when they name none.
func (self *Daemon) projectSettings() *SidecarProjectSettings {
	if self.settings.Project != nil {
		return self.settings.Project
	}
	return DefaultSidecarProjectSettings()
}

// $HOME, the search's bound.
func (self *Daemon) home() string {
	if self.settings.Home != "" {
		return self.settings.Home
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// The network a network-scoped call acts on (§5.8): argument, else the `.ur` found from hello's cwd, else the only
// network hosted. A *DaemonNetworkError when none is, which the daemon answers as FAILED_PRECONDITION.
func (self *Daemon) ResolveNetwork(hello *DaemonHello, argument string) (Id, error) {
	return self.resolveSessionNetwork(&daemonSession{hello: hello}, argument)
}

// ResolveNetwork on a session's `.ur`.
func (self *Daemon) resolveSessionNetwork(session *daemonSession, argument string) (Id, error) {
	if argument != "" {
		// an argument a person typed may be a legacy name; an agent's or a hook's never is (D-DNS-2)
		return self.resolveNetworkName(argument, session.hello.Mode == DaemonModeControl, true)
	}
	project, err := self.sessionProject(session)
	if err != nil {
		return Id{}, &DaemonNetworkError{Reason: "project", Networks: self.hostedNetworkNames()}
	}
	if project != nil && project.Network != "" {
		return self.resolveNetworkName(project.Network, false, false)
	}
	hosted := self.Sidecars()
	switch len(hosted) {
	case 0:
		return Id{}, &DaemonNetworkError{Reason: "none"}
	case 1:
		return hosted[0].NetworkId, nil
	}
	return Id{}, &DaemonNetworkError{Reason: "ambiguous", Networks: self.hostedNetworkNames()}
}

// The hosted network name names: a network id when idAllowed, else a label or alias by §12's rule, a legacy name only
// when interactive.
func (self *Daemon) resolveNetworkName(name string, interactive bool, idAllowed bool) (Id, error) {
	unknown := func() error {
		if len(self.Sidecars()) == 0 {
			return &DaemonNetworkError{Reason: "none"}
		}
		return &DaemonNetworkError{Reason: "unknown", Networks: self.hostedNetworkNames()}
	}
	if idAllowed {
		if networkId, err := ParseId(name); err == nil {
			if _, ok := self.SidecarForNetwork(networkId); ok {
				return networkId, nil
			}
			return Id{}, unknown()
		}
	}
	if self.settings.Labels == nil {
		return Id{}, unknown()
	}
	networkId, _, err := self.settings.Labels.ResolveNetworkLabel(self.settings.LabelRoot, name, interactive)
	if err != nil {
		var ambiguous *NetworkLabelAmbiguousError
		if errors.As(err, &ambiguous) {
			return Id{}, &DaemonNetworkError{Reason: "ambiguous", Networks: self.hostedNetworkNames()}
		}
		return Id{}, unknown()
	}
	if _, ok := self.SidecarForNetwork(networkId); !ok {
		return Id{}, unknown()
	}
	return networkId, nil
}

// Each hosted network's name for a person: its label under the daemon's root where the table holds one, else its
// alias, else its id.
func (self *Daemon) hostedNetworkNames() []string {
	rows := map[Id]NetworkLabelRow{}
	if table, ok := self.settings.Labels.(interface{ Networks() []NetworkLabelRow }); ok {
		root := canonicalNetworkLabelRoot(self.settings.LabelRoot)
		for _, row := range table.Networks() {
			if row.Root == root {
				rows[row.NetworkId] = row
			}
		}
	}
	names := []string{}
	for _, network := range self.Sidecars() {
		row := rows[network.NetworkId]
		switch {
		case row.Label != "":
			names = append(names, row.Label)
		case row.Alias != "":
			names = append(names, row.Alias)
		default:
			names = append(names, network.NetworkId.String())
		}
	}
	return names
}

// The code a refused network resolution answers.
func daemonNetworkErrorCode(err error) int {
	var networkErr *DaemonNetworkError
	if errors.As(err, &networkErr) {
		return DaemonRpcFailedPrecondition
	}
	return DaemonRpcFailed
}
