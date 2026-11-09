//go:build !js && !ios && !android && !sdk_mobile_bind

// The project file and a call's network (§5.8, CORE-M3-05; owner decisions 23, 170; D-DNS-2). `.ur` is TOML at a
// project root, holding no secret and safe to commit: `network`, a label or alias, `agent`, the default --agent, and
// `claims` and `project`, §16.11's announcement setting and label, which this file reads and CORE-M6-02 applies. The
// daemon finds it from the hello's cwd up, each directory's own `.ur` first, stopping after the git top level or $HOME.
//
// A committed `.ur` is hostile input, so it is read by a strict parser of this one flat form rather than a TOML module:
// at most 4 KiB of UTF-8 lines, each blank, a comment, or `key = "value"` with an optional trailing comment, the keys
// above once each, values in basic strings with no escape. Anything else is refused whole, and a refusal names its line
// number and nothing of the file.
//
// A network-scoped call acts on its network argument, else `.ur`'s, else the only network the daemon hosts; otherwise
// it fails with §5.8's FAILED_PRECONDITION naming the networks. A name resolves by §12's ResolveNetworkLabel: a label,
// an alias or a retiring alias, and a legacy network_name only as a person's typed input, a control-mode argument,
// never from `.ur` or a git remote, whose name another network may later hold. A network id names its network too.

package sidecar

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// The project file's format values.
const (
	sidecarProjectFileName = ".ur"
	// The longest `.ur` read: four short keys and their comments are far under it.
	sidecarProjectMaxByteCount = 4 * 1024
	// The longest value.
	sidecarProjectMaxValueByteCount = 64
)

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

// Parses one `.ur`'s bytes, refusing anything but the flat form.
func ParseSidecarProject(content []byte) (*SidecarProject, error) {
	if sidecarProjectMaxByteCount < len(content) || !utf8.Valid(content) || strings.HasPrefix(string(content), "\xef\xbb\xbf") {
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
			value == "" || sidecarProjectMaxValueByteCount < len(value) {
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

// Finds `.ur` from cwd up: each directory's own first, stopping after the git top level, a directory holding .git, or
// home, or at the root. Nil with no error when there is none, and for a cwd that is not absolute. A `.ur` that is not a
// regular file, cannot be read or does not parse is refused, never skipped, since the person meant it to scope.
func FindSidecarProject(cwd string, home string) (*SidecarProject, error) {
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
			if !info.Mode().IsRegular() || sidecarProjectMaxByteCount < info.Size() {
				return nil, sidecarProjectMalformed(0)
			}
			project, err := readSidecarProject(path)
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
func readSidecarProject(path string) (*SidecarProject, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, sidecarProjectMalformed(0)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, sidecarProjectMaxByteCount+1))
	if err != nil {
		return nil, sidecarProjectMalformed(0)
	}
	return ParseSidecarProject(content)
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
		session.project, session.projectErr = FindSidecarProject(session.hello.Cwd, self.home())
	}
	return session.project, session.projectErr
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
