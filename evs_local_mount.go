//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Mounts (§11.11, owner decision 24): `ur mount add <dir>` serves a repo to stock git from a plain bare repository the
// daemon owns, plaintext like the working tree (owner decision 47), while evs mirrors stay sealed. The registry keeps
// each mount in the evs component's sealed store, mounts/<repo_id>, so a daemon reopens them at start; an implicit
// mount (git-remote-ur's first use, §11.11's names row) has no working directory and no listener.
//
// Where things sit is the sealed mirror layout (evs_mirror_layout.go): a mount's bare repository and its hooks
// directory in the network's plaintext git tree, <state>/net/<network_id>/git/<repo>.git and <repo>.hooks, beside the
// sealed directory that holds its mirror, evs/mirror/<repo>/, and never inside it. Both paths follow from <state> and
// the ids alone, so a record names no path git could be sent to, and a moved <state> still finds its mounts. The tree
// keeps <state>'s modes, 0700 directories and 0600 files: each bare repository is created with
// core.sharedRepository 0600, so every file git writes there later is the user's alone too.
//
// On every mount's bare repository the daemon sets receive.procReceiveRefs to refs/heads and refs/tags, so every
// branch and tag update reaches its proc-receive hook (EVS1-M2-36), receive.advertiseAtomic to false, so `git push
// --atomic` fails before any write, and core.hooksPath to a directory the daemon owns. It also sets 8.2.11's upkeep
// (DESIGN-DETAILS 8.2.11): transfer.hideRefs refs/ur, so the daemon's own namespace is neither advertised nor taken
// from a client; git's own gc, receive's autogc and fsck off, the daemon running gc itself; receive's
// denyNonFastForwards and denyDeletes off and core.logAllRefUpdates off, force and delete being evs's to judge. The
// daemon's namespace refs/ur/ is made at the mount: evs's tips at refs/ur/evs/<ref_id> and an import's source at
// refs/ur/import/<id> (8.2.2). The bare repository is SHA-1 only (plan-EVS1-format-bytes#4). In a mount's working clone, ur mount add sets committer.name to the agent label and
// committer.email to <client_id>@ur.invalid (owner decision 81). A mount serves git-mode refs; evs refuses a push to a
// file-mode ref with REF_MODE, which the receive path reports as ng.
//
// Desktop legs only: mobile, wasm and the sdk run head mode, whose Mount refuses (evs_local_none.go). Safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// The registry's directory in the evs component's store.
const evsMountDirectory = "mounts/"

// The per-mount secret's length, a format value of plan-EVS1-git-http-credential.
const evsLocalHttpSecretByteCount = 32

// The namespace the daemon keeps in each bare repository, hidden from clients (DESIGN-DETAILS 8.2.2, 8.2.11).
const evsLocalDaemonRefPrefix = "refs/ur"

// The local tier's plaintext tree in a network's directory, and what each mount keeps there.
const (
	evsLocalGitDirectory      = "git"
	evsLocalBareRepoExtension = ".git"
	evsLocalHooksExtension    = ".hooks"
	// core.sharedRepository's value: <state>'s file mode, which git also turns into 0700 directories
	evsLocalSharedRepository = "0600"
)

// <state>/net/<network_id>/git: where a network's bare repositories and hooks sit, beside its sealed directories.
func evsLocalGitTree(state string, networkId Id) string {
	return filepath.Join(state, filepath.FromSlash(networkDirectoryPath(networkId)), evsLocalGitDirectory)
}

// One mount: its repo, the working directory it names, the bare repository the local git server runs on, and the
// repo's sealed mirror beside it.
type EvsLocalRepo struct {
	RepoId Id
	// Empty for an implicit mount.
	Dir     string
	BareDir string
	// The daemon-owned hooks directory, core.hooksPath.
	HooksDir   string
	AgentLabel string
	// The evs objects this device holds of the repo, sealed (evs_mirror_layout.go).
	Mirror *EvsMirrorStore
	locks  *EvsRefLocks
	git    *EvsGitRunner
	// the mount's sync engine (evs_local_sync.go), nil for a mount a test builds by hand
	sync *EvsGitSyncEngine
	// the per-mount secret git's http front takes as Basic's password (plan-EVS1-git-http-credential), nil for none
	httpSecret []byte
}

// The mount's locks: P_r, L_r and M (DESIGN-DETAILS 8.2.9).
func (self *EvsLocalRepo) Locks() *EvsRefLocks {
	return self.locks
}

// The mount's sync engine, nil for none.
func (self *EvsLocalRepo) Sync() *EvsGitSyncEngine {
	return self.sync
}

// The git runner the mount runs on.
func (self *EvsLocalRepo) GitRunner() *EvsGitRunner {
	return self.git
}

// Runs git on the bare repository.
func (self *EvsLocalRepo) Git(ctx context.Context, args ...string) ([]byte, error) {
	return self.git.Run(ctx, self.BareDir, args...)
}

// A mount's stored record. The paths are the layout's, never stored. The store seals it, so the http front's secret
// rests sealed with the rest of the evs component's state (§5.9).
type evsMountRecord struct {
	Dir        string `json:"dir,omitempty"`
	AgentLabel string `json:"agent_label,omitempty"`
	// 32 random bytes drawn at the first ur mount add (plan-EVS1-git-http-credential)
	HttpSecret []byte `json:"http_secret,omitempty"`
}

// One daemon's mounts.
type EvsMounts struct {
	client *EvsClient
	// <state>/net/<network_id>/git
	gitTree string
	git     *EvsGitRunner

	stateLock    sync.Mutex
	repoIdMounts map[Id]*EvsLocalRepo
	// the sync engine imports run through, nil until one is registered (EVS1-M2-35's)
	sync EvsGitSync
}

// The registry of client's mounts, its bare repositories in the plaintext git tree of client's network under state,
// §5.9's <state>, which the instance's store is rooted at, and its git. It attaches to the client, so EvsRepo.Mount
// reaches it.
func NewEvsMounts(client *EvsClient, state string, git *EvsGitRunner) (*EvsMounts, error) {
	if !filepath.IsAbs(state) {
		return nil, fmt.Errorf("%w: the mount state by an absolute path", errInvalidSettings)
	}
	self := &EvsMounts{
		client:       client,
		gitTree:      evsLocalGitTree(state, client.NetworkId()),
		git:          git,
		repoIdMounts: map[Id]*EvsLocalRepo{},
	}
	client.stateLock.Lock()
	client.localTier = self
	client.stateLock.Unlock()
	return self, nil
}

// The network's plaintext git tree.
func (self *EvsMounts) GitTree() string {
	return self.gitTree
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
		mount, err := self.localRepo(repoId, record)
		if err != nil {
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.repoIdMounts[repoId] = mount
		}()
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

// A mount of a record, at the layout's paths.
func (self *EvsMounts) localRepo(repoId Id, record *evsMountRecord) (*EvsLocalRepo, error) {
	mirror, err := self.client.Mirror(repoId)
	if err != nil {
		return nil, err
	}
	mount := &EvsLocalRepo{
		RepoId:     repoId,
		Dir:        record.Dir,
		BareDir:    filepath.Join(self.gitTree, evsUrlId(repoId)+evsLocalBareRepoExtension),
		HooksDir:   filepath.Join(self.gitTree, evsUrlId(repoId)+evsLocalHooksExtension),
		AgentLabel: record.AgentLabel,
		Mirror:     mirror,
		locks:      NewEvsRefLocks(self.client.settings, self.client.clock),
		git:        self.git,
		httpSecret: record.HttpSecret,
	}
	mount.sync = newEvsGitSyncEngine(self.client, mount)
	return mount, nil
}

// Mounts repoId: its bare repository created SHA-1 and configured, or reopened; the working clone's committer set
// when args names one that is a git repository; the record kept. An implicit mount names no directory.
func (self *EvsMounts) Add(ctx context.Context, repoId Id, args *EvsMountArgs) (*EvsLocalRepo, error) {
	if args.Dir != "" && !filepath.IsAbs(args.Dir) {
		return nil, fmt.Errorf("%w: a mount by a relative path", errInvalidSettings)
	}
	identity := self.client.args.Identity()
	label := args.AgentLabel
	if label == "" {
		label = identity.SidecarId.String()
	}
	record := &evsMountRecord{Dir: args.Dir, AgentLabel: label}
	if held, ok := self.Get(repoId); ok && 0 < len(held.httpSecret) {
		record.HttpSecret = held.httpSecret
	} else {
		record.HttpSecret = make([]byte, evsLocalHttpSecretByteCount)
		// never fails: since Go 1.24 a broken system generator crashes the program instead
		cryptorand.Read(record.HttpSecret)
	}
	mount, err := self.localRepo(repoId, record)
	if err != nil {
		return nil, err
	}
	// MkdirAll makes the tree's missing parents 0700 too
	if err := os.MkdirAll(mount.HooksDir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(mount.BareDir, "HEAD")); os.IsNotExist(err) {
		_, err := self.git.Run(ctx, "", "init", "--bare", "--quiet", "--object-format=sha1",
			"--shared="+evsLocalSharedRepository, mount.BareDir)
		if err != nil {
			return nil, err
		}
	}
	for _, setting := range [][]string{
		{"config", "--replace-all", "receive.procReceiveRefs", "refs/heads"},
		{"config", "--add", "receive.procReceiveRefs", "refs/tags"},
		{"config", "receive.advertiseAtomic", "false"},
		{"config", "core.hooksPath", mount.HooksDir},
		{"config", "core.sharedRepository", evsLocalSharedRepository},
		{"config", "--replace-all", "transfer.hideRefs", evsLocalDaemonRefPrefix},
		{"config", "gc.auto", "0"},
		{"config", "receive.autogc", "false"},
		{"config", "transfer.fsckObjects", "false"},
		{"config", "receive.denyNonFastForwards", "false"},
		{"config", "receive.denyDeletes", "false"},
		{"config", "core.logAllRefUpdates", "false"},
	} {
		if _, err := self.git.Run(ctx, mount.BareDir, setting...); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Join(mount.BareDir, filepath.FromSlash(evsLocalDaemonRefPrefix)), 0o700); err != nil {
		return nil, err
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
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held := self.repoIdMounts[repoId]; held != nil {
		// the same mount again: its locks and its engine, which may be mid-replay, stay
		mount.locks, mount.sync = held.locks, held.sync
	}
	self.repoIdMounts[repoId] = mount
	return mount, nil
}

// Every mount, by repo id.
func (self *EvsMounts) List() []*EvsLocalRepo {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	mounts := make([]*EvsLocalRepo, 0, len(self.repoIdMounts))
	for _, mount := range self.repoIdMounts {
		mounts = append(mounts, mount)
	}
	slices.SortFunc(mounts, func(a *EvsLocalRepo, b *EvsLocalRepo) int { return bytes.Compare(a.RepoId[:], b.RepoId[:]) })
	return mounts
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
