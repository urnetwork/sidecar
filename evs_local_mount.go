//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Mounts (§11.11, owner decision 24): `ur mount add <dir>` serves a repo to stock git from a plain bare repository the
// daemon owns, plaintext like the working tree (owner decision 47), while evs mirrors stay sealed. The registry keeps
// each mount in the evs component's sealed store, mounts/<repo_id>, so a daemon reopens them at start; an implicit
// mount (git-remote-ur's first use, §11.11's names row) has no working directory and no listener.
//
// On every mount's bare repository the daemon sets receive.procReceiveRefs to refs/heads and refs/tags, so every
// branch and tag update reaches its proc-receive hook (EVS1-M2-36), receive.advertiseAtomic to false, so `git push
// --atomic` fails before any write, and core.hooksPath to a directory the daemon owns. The bare repository is SHA-1
// only (plan-EVS1-format-bytes#4). In a mount's working clone, ur mount add sets committer.name to the agent label and
// committer.email to <client_id>@ur.invalid (owner decision 81). A mount serves git-mode refs; evs refuses a push to a
// file-mode ref with REF_MODE, which the receive path reports as ng.
//
// Desktop legs only: mobile, wasm and the sdk run head mode, whose Mount refuses (evs_local_none.go). Safe for
// concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The registry's directory in the evs component's store.
const evsMountDirectory = "mounts/"

// One mount: its repo, the working directory it names, and the bare repository the local git server runs on.
type EvsLocalRepo struct {
	RepoId Id
	// Empty for an implicit mount.
	Dir     string
	BareDir string
	// The daemon-owned hooks directory, core.hooksPath.
	HooksDir   string
	AgentLabel string
	locks      *EvsRefLocks
	git        *EvsGitRunner
}

// Takes the ref's daemon lock, which receive-pack's update and the sync engine's apply both hold (§11.11's locks row).
func (self *EvsLocalRepo) LockRef(ctx context.Context, ref string) (func(), error) {
	return self.locks.Lock(ctx, ref)
}

// Runs git on the bare repository.
func (self *EvsLocalRepo) Git(ctx context.Context, args ...string) ([]byte, error) {
	return self.git.Run(ctx, self.BareDir, args...)
}

// A mount's stored record.
type evsMountRecord struct {
	Dir        string `json:"dir,omitempty"`
	BareDir    string `json:"bare_dir"`
	HooksDir   string `json:"hooks_dir"`
	AgentLabel string `json:"agent_label,omitempty"`
}

// One daemon's mounts.
type EvsMounts struct {
	client *EvsClient
	// the daemon's state directory, where bare repositories and hooks live
	stateDir string
	git      *EvsGitRunner

	stateLock    sync.Mutex
	repoIdMounts map[Id]*EvsLocalRepo
}

// The registry of client's mounts, its bare repositories under stateDir, and its git. It attaches to the client, so
// EvsRepo.Mount reaches it.
func NewEvsMounts(client *EvsClient, stateDir string, git *EvsGitRunner) (*EvsMounts, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, fmt.Errorf("%w: the mount state by an absolute path", errInvalidSettings)
	}
	self := &EvsMounts{client: client, stateDir: stateDir, git: git, repoIdMounts: map[Id]*EvsLocalRepo{}}
	client.stateLock.Lock()
	client.localTier = self
	client.stateLock.Unlock()
	return self, nil
}

// Reopens every mount the store records.
func (self *EvsMounts) Load(ctx context.Context) error {
	store := self.client.args.Store
	entries, err := store.List(evsMountDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		repoId, err := ParseId(strings.TrimPrefix(entry.Name, evsMountDirectory))
		if err != nil {
			continue
		}
		reader, err := store.Open(entry.Name)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return err
		}
		record := &evsMountRecord{}
		if err := json.Unmarshal(data, record); err != nil {
			return fmt.Errorf("%w: a mount record that does not parse", ErrSidecarStoreFailed)
		}
		self.stateLock.Lock()
		self.repoIdMounts[repoId] = self.localRepo(repoId, record)
		self.stateLock.Unlock()
	}
	return nil
}

// The mount of repoId, false when none.
func (self *EvsMounts) Get(repoId Id) (*EvsLocalRepo, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	mount, ok := self.repoIdMounts[repoId]
	return mount, ok
}

// A mount of a record.
func (self *EvsMounts) localRepo(repoId Id, record *evsMountRecord) *EvsLocalRepo {
	return &EvsLocalRepo{
		RepoId:     repoId,
		Dir:        record.Dir,
		BareDir:    record.BareDir,
		HooksDir:   record.HooksDir,
		AgentLabel: record.AgentLabel,
		locks:      NewEvsRefLocks(self.client.settings, self.client.clock),
		git:        self.git,
	}
}

// Mounts repoId: its bare repository created SHA-1 and configured, or reopened; the working clone's committer set
// when args names one that is a git repository; the record kept. An implicit mount names no directory.
func (self *EvsMounts) Add(ctx context.Context, repoId Id, args *EvsMountArgs) (*EvsLocalRepo, error) {
	if args.Dir != "" && !filepath.IsAbs(args.Dir) {
		return nil, fmt.Errorf("%w: a mount by a relative path", errInvalidSettings)
	}
	bareDir := filepath.Join(self.stateDir, "mounts", evsUrlId(repoId)+".git")
	hooksDir := filepath.Join(self.stateDir, "mounts", evsUrlId(repoId)+".hooks")
	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(bareDir, "HEAD")); os.IsNotExist(err) {
		if _, err := self.git.Run(ctx, "", "init", "--bare", "--quiet", "--object-format=sha1", bareDir); err != nil {
			return nil, err
		}
	}
	for _, setting := range [][]string{
		{"config", "--replace-all", "receive.procReceiveRefs", "refs/heads"},
		{"config", "--add", "receive.procReceiveRefs", "refs/tags"},
		{"config", "receive.advertiseAtomic", "false"},
		{"config", "core.hooksPath", hooksDir},
	} {
		if _, err := self.git.Run(ctx, bareDir, setting...); err != nil {
			return nil, err
		}
	}
	identity := self.client.args.Identity()
	label := args.AgentLabel
	if label == "" {
		label = identity.SidecarId.String()
	}
	if args.Dir != "" {
		if _, err := os.Stat(filepath.Join(args.Dir, ".git")); err == nil {
			for _, setting := range [][]string{
				{"config", "committer.name", label},
				{"config", "committer.email", identity.ClientId.String() + evsCommitterDomain},
			} {
				if _, err := self.git.Run(ctx, args.Dir, setting...); err != nil {
					return nil, err
				}
			}
		}
	}
	record := &evsMountRecord{Dir: args.Dir, BareDir: bareDir, HooksDir: hooksDir, AgentLabel: label}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	writer, err := self.client.args.Store.Create(evsMountDirectory + repoId.String())
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Commit(); err != nil {
		return nil, err
	}
	mount := self.localRepo(repoId, record)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held := self.repoIdMounts[repoId]; held != nil {
		mount.locks = held.locks
	}
	self.repoIdMounts[repoId] = mount
	return mount, nil
}

// Serves the repo to stock git from a plaintext bare repository (§11.11): the client's mount registry adds or
// reopens it.
func (self *EvsRepo) Mount(ctx context.Context, args *EvsMountArgs) (*EvsMountInfo, error) {
	mounts := func() *EvsMounts {
		self.client.stateLock.Lock()
		defer self.client.stateLock.Unlock()
		mounts, _ := self.client.localTier.(*EvsMounts)
		return mounts
	}()
	if mounts == nil {
		return nil, fmt.Errorf("%w: this client has no mount registry", ErrEvsNotBuilt)
	}
	mount, err := mounts.Add(ctx, self.repoId, args)
	if err != nil {
		return nil, err
	}
	return &EvsMountInfo{RepoId: self.repoId, Dir: mount.Dir, BareDir: mount.BareDir}, nil
}
