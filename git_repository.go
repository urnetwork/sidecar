//go:build !ios_extension && !sidecar_http

// A bundled git repository (DESIGN-COMPUTE §13.4, D-GIT-1; GIT-M13-01): a worktree and its .git, in git's own on-disk
// layout, so stock git can open a full clone on a desktop for debugging:
//
//	.git/HEAD, .git/refs/{heads,tags,remotes/origin}, .git/objects (loose objects only), .git/index (version 2),
//	.git/config (gitWriteConfig's clean form), and nothing that runs: no hooks directory, no info/attributes
//	.git/ur/  this git's own state, which stock git passes over: the file system's habits, the porcelain's state
//	          (its one remote and the branches' upstreams, the sparse prefix), and GIT-M13-02's replay states and
//	          promisor table
//
// The porcelain's state, not .git/config, is what its commands read for the remote and the branches: config is read
// for user.* alone (§13.7), and rendered from the state on every open and change, so whatever else it held is gone
// before a command runs. A repository whose config states a format this git does not read (a version but 0, any
// extension, a sha256 repository's objectformat among them) is refused before anything is written.
//
// On every leg but the forwarding role's and the page Worker's (GIT-M13-08 brings the page leg). A GitRepository is one
// command's: not safe for concurrent use; the index and ref locks order commands and stock git.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
)

// The porcelain's state file.
const gitStateName = ".git/ur/state"

var (
	// A directory that holds a repository already, where one is to be made.
	ErrGitRepositoryExists = errors.New("git: the directory holds a repository already")
	// A directory that holds no repository this git opens.
	ErrGitNoRepository = errors.New("git: not a git repository")
)

// The porcelain's state (.git/ur/state): see the file header.
type gitRepositoryState struct {
	Version int `json:"version"`
	// The one remote, ur://<net>/<repo>; "" for none.
	Remote string `json:"remote,omitempty"`
	// Each branch's upstream.
	Branches []GitConfigBranch `json:"branches,omitempty"`
	// The sparse prefix the worktree checks out (GIT-M13-02), "" for every path.
	Sparse string `json:"sparse,omitempty"`
}

// The state's one version.
const gitRepositoryStateVersion = 1

// One repository: see the file header.
type GitRepository struct {
	fileSystem GitFileSystem
	settings   *GitSettings
	objects    *GitObjectStore
	refs       *GitRefs
	worktree   *GitWorktree
	state      *gitRepositoryState
	userName   string
	userEmail  string
}

// What a new repository is made with.
type GitInitArgs struct {
	// The worktree's file system, its root the worktree, which holds no .git yet.
	FileSystem GitFileSystem
	Settings   *GitSettings
	// The one remote, ur://<net>/<repo> (GitRemoteUrl's form, GIT-M13-02); "" for none yet.
	Remote string
	// The branch HEAD names, born at the first commit or clone: main when empty.
	Branch string
	// The sparse prefix (GIT-M13-02), "" for every path.
	Sparse string
}

// Makes a repository's .git in an empty worktree: the layout, HEAD on its branch, the probed habits, the state and
// the clean config.
func InitGitRepository(ctx context.Context, args *GitInitArgs) (*GitRepository, error) {
	settings := args.Settings
	if settings == nil {
		settings = DefaultGitSettings()
	}
	fileSystem := args.FileSystem
	if _, err := fileSystem.Lstat(".git"); err == nil {
		return nil, ErrGitRepositoryExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	branch := args.Branch
	if branch == "" {
		branch = string(EvsMainRefName)
	}
	if err := GitCheckRefName(GitBranchPrefix + branch); err != nil {
		return nil, err
	}
	if args.Sparse != "" {
		if err := gitCheckPath(strings.TrimSuffix(args.Sparse, "/"), 0); err != nil {
			return nil, err
		}
	}
	for _, directory := range []string{
		gitObjectsDirectory + "/info", gitObjectsDirectory + "/pack", ".git/refs/heads", ".git/refs/tags",
		gitUrTempDirectory,
	} {
		if err := fileSystem.MkdirAll(directory, 0o755); err != nil {
			return nil, err
		}
	}
	habits, err := gitProbeHabits(fileSystem)
	if err != nil {
		return nil, err
	}
	if err := gitWriteHabits(fileSystem, habits); err != nil {
		return nil, err
	}
	repository := &GitRepository{
		fileSystem: fileSystem, settings: settings,
		state: &gitRepositoryState{Version: gitRepositoryStateVersion, Remote: args.Remote, Sparse: gitSparsePrefix(args.Sparse)},
	}
	repository.wire(habits)
	if err := repository.refs.SetHead(&GitHead{Symbolic: GitBranchPrefix + branch}); err != nil {
		return nil, err
	}
	if err := repository.saveState(); err != nil {
		return nil, err
	}
	return repository, nil
}

// A sparse prefix as the state keeps it: a directory's path with a trailing slash, "" for none.
func gitSparsePrefix(sparse string) string {
	sparse = strings.Trim(sparse, "/")
	if sparse == "" {
		return ""
	}
	return sparse + "/"
}

// What an existing repository is opened with.
type GitOpenArgs struct {
	// The worktree's file system, its root the worktree.
	FileSystem GitFileSystem
	Settings   *GitSettings
}

// Opens the repository of a worktree: its layout checked, its format read and refused where this git does not read
// it, its habits read (probed and kept where a repository stock git made has none), its config rendered clean.
func OpenGitRepository(ctx context.Context, args *GitOpenArgs) (*GitRepository, error) {
	settings := args.Settings
	if settings == nil {
		settings = DefaultGitSettings()
	}
	fileSystem := args.FileSystem
	for _, name := range []string{gitHeadName, gitObjectsDirectory, ".git/refs"} {
		if _, err := fileSystem.Lstat(name); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, ErrGitNoRepository
			}
			return nil, err
		}
	}
	read, err := gitReadConfig(fileSystem, settings)
	if errors.Is(err, fs.ErrNotExist) {
		read = &gitConfigRead{}
	} else if err != nil {
		return nil, err
	}
	if err := fileSystem.MkdirAll(gitUrTempDirectory, 0o755); err != nil {
		return nil, err
	}
	habits, err := gitReadHabits(fileSystem, settings)
	if err != nil {
		return nil, err
	}
	if habits == nil {
		if habits, err = gitProbeHabits(fileSystem); err != nil {
			return nil, err
		}
		if err := gitWriteHabits(fileSystem, habits); err != nil {
			return nil, err
		}
	}
	state := &gitRepositoryState{Version: gitRepositoryStateVersion}
	content, err := gitReadFile(fileSystem, gitStateName, settings.StateFileByteCount)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(content, state); err != nil || state.Version != gitRepositoryStateVersion {
			return nil, fmt.Errorf("%w: .git/ur/state does not read", ErrGitNoRepository)
		}
	}
	repository := &GitRepository{
		fileSystem: fileSystem, settings: settings, state: state, userName: read.userName, userEmail: read.userEmail,
	}
	repository.wire(habits)
	if _, err := repository.refs.Head(); err != nil {
		return nil, err
	}
	// whatever else the config held is gone before a command runs
	if err := repository.writeConfig(); err != nil {
		return nil, err
	}
	return repository, nil
}

// Builds the store, refs and worktree over the file system.
func (self *GitRepository) wire(habits *GitWorktreeHabits) {
	self.objects = newGitObjectStore(self.fileSystem, self.settings)
	self.refs = newGitRefs(self.fileSystem, self.settings)
	self.worktree = newGitWorktree(self.fileSystem, self.settings, self.objects, habits)
}

// The object store.
func (self *GitRepository) Objects() *GitObjectStore {
	return self.objects
}

// The refs.
func (self *GitRepository) Refs() *GitRefs {
	return self.refs
}

// The worktree.
func (self *GitRepository) Worktree() *GitWorktree {
	return self.worktree
}

// The settings it runs with.
func (self *GitRepository) Settings() *GitSettings {
	return self.settings
}

// The worktree's file system.
func (self *GitRepository) FileSystem() GitFileSystem {
	return self.fileSystem
}

// user.name and user.email as .git/config holds them, "" for none: a commit's author where set (§13.4).
func (self *GitRepository) User() (string, string) {
	return self.userName, self.userEmail
}

// The one remote, ur://<net>/<repo>, "" for none.
func (self *GitRepository) Remote() string {
	return self.state.Remote
}

// The sparse prefix the worktree checks out, "" for every path.
func (self *GitRepository) Sparse() string {
	return self.state.Sparse
}

// Each branch's upstream, by name.
func (self *GitRepository) Branches() []GitConfigBranch {
	return slices.Clone(self.state.Branches)
}

// Sets the one remote, kept in the state and the config; a remote the config cannot hold changes nothing.
func (self *GitRepository) SetRemote(remote string) error {
	previous := self.state.Remote
	self.state.Remote = remote
	if err := self.saveState(); err != nil {
		self.state.Remote = previous
		return err
	}
	return nil
}

// Sets a branch's upstream on origin (merge, refs/heads/<b>), kept in the state and the config; an empty merge drops
// it.
func (self *GitRepository) SetUpstream(branch string, merge string) error {
	if err := GitCheckRefName(GitBranchPrefix + branch); err != nil {
		return err
	}
	if merge != "" {
		if err := GitCheckRefName(merge); err != nil {
			return err
		}
	}
	previous := slices.Clone(self.state.Branches)
	self.state.Branches = slices.DeleteFunc(self.state.Branches, func(held GitConfigBranch) bool { return held.Name == branch })
	if merge != "" {
		self.state.Branches = append(self.state.Branches, GitConfigBranch{Name: branch, Merge: merge})
		slices.SortFunc(self.state.Branches, func(a GitConfigBranch, b GitConfigBranch) int { return strings.Compare(a.Name, b.Name) })
	}
	if err := self.saveState(); err != nil {
		self.state.Branches = previous
		return err
	}
	return nil
}

// Sets the sparse prefix, kept in the state.
func (self *GitRepository) setSparse(sparse string) error {
	previous := self.state.Sparse
	self.state.Sparse = gitSparsePrefix(sparse)
	if err := self.saveState(); err != nil {
		self.state.Sparse = previous
		return err
	}
	return nil
}

// Keeps the state and renders the config from it: the config rendered first, so a state it cannot hold writes
// nothing.
func (self *GitRepository) saveState() error {
	if _, err := gitRenderConfig(self.config()); err != nil {
		return err
	}
	content, err := json.Marshal(self.state)
	if err != nil {
		return err
	}
	if err := gitWriteFileAtomic(self.fileSystem, gitUrDirectory, gitStateName, content, 0o644, false); err != nil {
		return err
	}
	return self.writeConfig()
}

// The config the state and user.* render.
func (self *GitRepository) config() *GitConfig {
	return &GitConfig{RemoteUrl: self.state.Remote, Branches: self.state.Branches, UserName: self.userName, UserEmail: self.userEmail}
}

// Renders .git/config from the state and user.*.
func (self *GitRepository) writeConfig() error {
	return gitWriteConfig(self.fileSystem, self.config())
}
