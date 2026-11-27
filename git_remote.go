//go:build !ios_extension && !sidecar_http

// The bundled git's one kind of remote (DESIGN-COMPUTE §13.4's remote row, Q-GIT-2; GIT-M13-02): ur://<net>/<repo>,
// DESIGN §11.11's names, so the local Harness reaches nothing but EVS. <net> is a network's label or alias, which the
// caller resolves to the network's evs client; <repo> is id:<repo_id>, the id dashed or as 32 hex digits, as the
// local tier's git-remote-ur takes it, a display name refused until the config repo carries repos' names. Every other
// remote, http, https, ssh, git, file, scp's host:path and a local path among them, answers "not supported by ur git"
// (the owner's answer to Q-GIT-2, QD-1305: a GitHub remote would be network access by another name; enclaves use the
// system git for GitHub, through their egress).
//
// Package-level functions, safe for concurrent use.

package sidecar

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The scheme the one remote takes.
const gitRemoteScheme = "ur://"

var (
	// A remote of any kind but ur://: Q-GIT-2's answer.
	ErrGitRemoteUnsupported = errors.New("not supported by ur git: the only remote is ur://<net>/<repo>, EVS")
	// A ur:// remote whose <net> or <repo> does not read.
	ErrGitRemoteInvalid = errors.New("git: a remote that is not ur://<net>/id:<repo_id>")
)

// A remote, ur://<net>/<repo>.
type GitRemoteUrl struct {
	// The network's label or alias, as the URL names it, which the caller resolves.
	Network string
	// The repo.
	RepoId Id
}

// Reads a remote: see the file header.
func ParseGitRemoteUrl(url string) (*GitRemoteUrl, error) {
	rest, found := strings.CutPrefix(url, gitRemoteScheme)
	if !found {
		return nil, ErrGitRemoteUnsupported
	}
	network, repo, cut := strings.Cut(strings.TrimSuffix(rest, "/"), "/")
	if !cut || network == "" || repo == "" || strings.Contains(repo, "/") || strings.ContainsAny(url, " \t\r\n\x00\"\\#;") {
		return nil, ErrGitRemoteInvalid
	}
	idText, found := strings.CutPrefix(repo, "id:")
	if !found {
		return nil, fmt.Errorf("%w: repos are named id:<repo_id> until the config repo carries their names", ErrGitRemoteInvalid)
	}
	if repoId, err := ParseId(idText); err == nil {
		return &GitRemoteUrl{Network: network, RepoId: repoId}, nil
	}
	decoded, err := hex.DecodeString(idText)
	if err != nil || len(decoded) != len(Id{}) {
		return nil, fmt.Errorf("%w: id:<repo_id> takes a repo id", ErrGitRemoteInvalid)
	}
	return &GitRemoteUrl{Network: network, RepoId: Id(decoded)}, nil
}

// The remote as a URL, its repo by its dashed id.
func (self *GitRemoteUrl) String() string {
	return gitRemoteScheme + self.Network + "/id:" + self.RepoId.String()
}
